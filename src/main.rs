mod display;
mod ping;

use clap::Parser;
use std::{
    collections::VecDeque,
    net::{self},
    time::Instant,
};

use crate::display::DisplayModeTrait;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Number of packets per second
    #[arg(short, long)]
    rate: Option<u32>,

    /// Packet interval in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    interval: u64,

    /// Number of attempts (default infinite)
    #[arg(short, long)]
    count: Option<u32>,

    /// Timeout waiting for response in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    timeout: u64,

    /// Length
    #[arg(short, long, default_value_t = 64)]
    length: usize,

    /// Address or name of target host
    #[arg()]
    target: String,

    /// Display mode
    #[arg(short, long, default_value = "classic")]
    display: display::DisplayMode,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // for dur in [Duration::from_millis(1), Duration::from_millis(10), Duration::from_millis(100), Duration::from_millis(1000)] {
    //     println!("{} -> {:?}", dur.as_millis(), latency_to_color(dur));
    // }
    // return Ok(());

    let args = Args::parse();
    let target = dns_lookup::lookup_host(&args.target).unwrap();
    let target = target.first().unwrap();
    let target_sa = match target {
        net::IpAddr::V4(v4addr) => net::SocketAddr::V4(net::SocketAddrV4::new(*v4addr, 58)),
        net::IpAddr::V6(v6addr) => net::SocketAddr::V6(net::SocketAddrV6::new(*v6addr, 58, 0, 0)),
    };

    let interval = match args.rate {
        Some(rate) => std::time::Duration::from_secs(1) / rate,
        None => std::time::Duration::from_millis(args.interval),
    };

    let mut next_send = std::time::Instant::now();
    let mut ping_protocol = ping::PingProtocol::new(target_sa, args.length)?;

    let mut sequence = 0u64;

    let time_reference = Instant::now();

    let mut attempts_left = args.count.unwrap_or(u32::MAX);

    let (columns, rows) = match crossterm::terminal::size() {
        Ok((w, h)) => (w - 1, h),
        Err(_) => (78, 25),
    };

    struct Entry {
        sequence: u64,
        timeout: std::time::Instant,
        received: bool,
    }

    let mut entries = VecDeque::new();

    let mut display_mode: Box<dyn display::DisplayModeTrait> = match args.display {
        display::DisplayMode::Classic => Box::new(display::ClassicDisplayMode::new(columns, rows)),
        display::DisplayMode::Char => Box::new(display::CharDisplayMode::new(columns, rows)),
        display::DisplayMode::Dumb => Box::new(display::DumbDisplayMode::new(columns, rows)),
        display::DisplayMode::CharGraph => {
            Box::new(display::CharGraphDisplayMode::new(columns, rows))
        }
    };

    let icmp_timeout = std::time::Duration::from_millis(args.timeout);

    while attempts_left > 0 || !entries.is_empty() {
        if attempts_left > 0 {
            let timestamp = time_reference.elapsed().as_nanos() as u64;
            let icmp_sequence = sequence as u16;
            ping_protocol.send(icmp_sequence, timestamp).unwrap();

            display_mode.display_send(target, args.length, sequence)?;

            attempts_left -= 1;

            entries.push_back(Entry {
                sequence,
                timeout: std::time::Instant::now() + icmp_timeout,
                received: false,
            });
            sequence += 1;
            next_send += interval;
        }

        // Receive loop
        loop {
            // Clean up entries that have timed out
            while !entries.is_empty() {
                let entry = entries.front().unwrap();
                if entry.received {
                    // Remove all entries from front of queue that have been received
                    entries.pop_front();
                } else if entry.timeout > std::time::Instant::now() {
                    // Stop if the next entry has not yet timed out
                    break;
                } else {
                    display_mode.display_timeout(entry.sequence)?;
                    entries.pop_front();
                }
            }

            if entries.is_empty() && attempts_left == 0 {
                break;
            }

            // Determine how long to wait until the next event
            let wait_until = if attempts_left > 0 {
                if entries.is_empty() {
                    next_send // Wait for next send
                } else {
                    next_send.min(entries.front().unwrap().timeout) // Wait for next timeout or next send
                }
            } else if entries.is_empty() {
                break; // No more attempts left and no more entries to wait for
            } else {
                entries.front().unwrap().timeout // Wait for next timeout
            };

            let time_left = wait_until - std::time::Instant::now();

            let response = ping_protocol.recv(time_left).unwrap();
            if let Some((_addr, _identifier, rx_sequence, tx_timestamp, rx_time)) = response {
                let rx_timestamp = (rx_time - time_reference).as_nanos() as u64;
                if tx_timestamp > rx_timestamp {
                    continue; // Ignore responses that were sent after the receive timestamp
                }
                let nanos = rx_timestamp - tx_timestamp;
                let round_trip_time = std::time::Duration::from_nanos(nanos);

                if !entries.is_empty() {
                    let front_sequence = entries.front().unwrap().sequence;
                    let position = (rx_sequence as usize + 65536 - front_sequence as usize) % 65536;
                    if position <= entries.len() {
                        let entry = &entries[position];
                        display_mode.display_receive(entry.sequence, round_trip_time)?;
                        if position == 0 {
                            entries.pop_front();
                        } else {
                            entries[position].received = true;
                        }
                    }
                }
            }

            if attempts_left > 0 && (next_send - std::time::Instant::now()).is_zero() {
                break; // Break receive loop and send next request
            }
        }
    }
    Ok(())
}
