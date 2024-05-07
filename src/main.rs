mod display;
mod ping;

use clap::Parser;
use std::{
    collections::VecDeque,
    net,
    time::{Duration, Instant},
};

use crate::{display::DisplayModeTrait, ping::Pinger};

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
    #[arg(short = 'w', long, default_value_t = 1000)]
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

    /// Time to live
    #[arg(short, long, default_value_t = 64)]
    ttl: u8,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

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

    ping_protocol.set_ttl(args.ttl).expect("Failed to set TTL");

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
        display::DisplayMode::CharGraph => Box::new(display::CharGraphDisplayMode::new(columns, rows)),
        display::DisplayMode::Debug => Box::new(display::DebugDisplayMode::new(columns, rows)),
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
            if let Ok(()) = rx.try_recv() {
                if attempts_left > 0 {
                    attempts_left = 0;
                } else {
                    entries.clear();
                    break;
                }
            }

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

            // Ensure that Ctrl-C is responsive
            let time_left = time_left.min(Duration::from_millis(50));

            let response = ping_protocol.recv(time_left)?;
            match response {
                ping::IcmpResult::IcmpPacket(packet) => {
                    if let Some(tx_timestamp) = packet.message.timestamp {
                        let rx_timestamp = (packet.time - time_reference).as_nanos() as u64;

                        if tx_timestamp > rx_timestamp || entries.is_empty() {
                            continue; // Ignore responses that were sent after the receive timestamp
                        }
                        let nanos = rx_timestamp - tx_timestamp;
                        let round_trip_time = std::time::Duration::from_nanos(nanos);
                        let front_sequence = entries.front().unwrap().sequence;
                        let position = (packet.message.seq as usize + 65536 - front_sequence as usize) % 65536;
                        if position <= entries.len() {
                            let entry = &entries[position];
                            display_mode.display_receive(entry.sequence, &packet, round_trip_time)?;
                            if position == 0 {
                                entries.pop_front();
                            } else {
                                entries[position].received = true;
                            }
                        }
                    }
                }
                ping::IcmpResult::RecvError(error) => {
                    if entries.is_empty() {
                        continue;
                    }
                    if let Some(orig_message) = &error.original_message {
                        let orig_sequence = orig_message.seq;
                        let front_sequence = entries.front().unwrap().sequence;
                        let position = (orig_sequence as usize + 65536 - front_sequence as usize) % 65536;
                        if position <= entries.len() {
                            let entry = &entries[position];
                            display_mode.display_error(entry.sequence, &error)?;
                            if position == 0 {
                                entries.pop_front();
                            } else {
                                entries[position].received = true;
                            }
                        }
                    }
                }
                ping::IcmpResult::Timeout => (),
                ping::IcmpResult::Interrupted => (),
            }

            if attempts_left > 0 && (next_send - std::time::Instant::now()).is_zero() {
                break; // Break receive loop and send next request
            }
        }
    }

    display_mode.close()?;
    Ok(())
}
