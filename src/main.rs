mod ping;

use clap::Parser;
use crossterm::QueueableCommand;
use std::{collections::VecDeque, io::Write, net, time::Instant};

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

    /// Address or name of target host
    #[arg()]
    target: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let mut ping_protocol = ping::PingProtocol::new(target_sa)?;

    let mut sequence = 0u16;

    let time_reference = Instant::now();

    let mut stdout = std::io::stdout();

    let target_str = target.to_string();

    let mut attempts_left = args.count.unwrap_or(u32::MAX);

    struct Entry {
        sequence: u16,
        timeout: std::time::Instant,
        received: bool,
    }

    let mut entries = VecDeque::new();

    while attempts_left > 0 || !entries.is_empty() {
        if attempts_left > 0 {
            let timestamp = time_reference.elapsed().as_nanos() as u64;
            ping_protocol.send(sequence, timestamp).unwrap();
            println!("{}: icmp_seq={}", target_str, sequence);
            attempts_left -= 1;

            entries.push_back(Entry {
                sequence,
                timeout: std::time::Instant::now() + std::time::Duration::from_millis(args.timeout),
                received: false,
            });
            sequence += 1;
            next_send += interval;
        }

        loop {
            while !entries.is_empty() {
                let entry = entries.front().unwrap();
                if entry.received {
                    // Remove all entries from front of queue that have been received
                    entries.pop_front();
                } else if entry.timeout > std::time::Instant::now() {
                    // Stop if the next entry has not yet timed out
                    break;
                } else {
                    // Print timeout message and remove entry
                    let relative_sequence = sequence - entry.sequence;
                    stdout.queue(crossterm::cursor::SavePosition)?;
                    stdout.queue(crossterm::cursor::MoveUp(relative_sequence))?;
                    let digits = match entry.sequence {
                        0 => 1,
                        n => (n as f64).log10() as u16 + 1,
                    };
                    stdout.queue(crossterm::cursor::MoveRight(
                        12 + target_str.len() as u16 + digits,
                    ))?;
                    print!("timeout");
                    stdout.queue(crossterm::cursor::RestorePosition)?;
                    stdout.flush()?;
                    entries.pop_front();
                    // println!("{}", entries.len());
                }
            }

            if attempts_left > 0 && (next_send - std::time::Instant::now()).is_zero() {
                // Break receive loop and send next request
                break;
            }

            // println!("attempt_left = {}, entries.len() = {}", attempts_left, entries.len());

            //dbg!("next_send_in = {:?}", next_send - std::time::Instant::now());

            let wait_for = if attempts_left > 0 {
                if entries.is_empty() {
                    // Wait for next send
                    //dbg!("wait_next_send");
                    next_send
                } else {
                    // Wait for next timeout or next send
                    //dbg!("wait_next_timeout_or_send");
                    next_send.min(entries.front().unwrap().timeout)
                }
            } else if entries.is_empty() {
                // No more attempts left and no more entries to wait for
                //dbg!("wait_no_more_attempts_or_entries");
                break;
            } else {
                // Wait for next timeout
                //dbg!("wait_next_timeout {}", entries.len());
                entries.front().unwrap().timeout
            };

            let time_left = wait_for - std::time::Instant::now();
            if time_left.is_zero() {
                if attempts_left == 0 {
                    return Ok(());
                }
                break;
            }

            //dbg!("time_left = {:?}", time_left);

            let response = ping_protocol.recv(time_left).unwrap();
            if let Some((_addr, _identifier, rx_sequence, tx_timestamp, rx_time)) = response {
                // println!("rx_time = {:?}", rx_time);
                // println!("timestamp = {:?}", timestamp);
                let rx_timestamp = (rx_time - time_reference).as_nanos() as u64;
                if tx_timestamp > rx_timestamp {
                    // Ignore packets that were sent after the response was received (quantum packets)
                    continue;
                }
                let nanos = rx_timestamp - tx_timestamp;
                let round_trip_time = std::time::Duration::from_nanos(nanos);
                let relative_sequence = (sequence as usize + 65536 - rx_sequence as usize) % 65536;
                if relative_sequence >= 80 {
                    // Ignore packets that are too old
                    continue;
                }
                stdout.queue(crossterm::cursor::SavePosition)?;
                stdout.queue(crossterm::cursor::MoveUp(relative_sequence as u16))?;
                let digits = match rx_sequence {
                    0 => 1,
                    n => (n as f64).log10() as u16 + 1,
                };
                stdout.queue(crossterm::cursor::MoveRight(
                    12 + target_str.len() as u16 + digits,
                ))?;
                print!("time={:?}", round_trip_time);
                stdout.queue(crossterm::cursor::RestorePosition)?;
                stdout.flush()?;

                if !entries.is_empty() {
                    let front_sequence = entries.front().unwrap().sequence;
                    let position = (rx_sequence as usize + 65536 - front_sequence as usize) % 65536;
                    if position <= entries.len() {
                        if position == 0 {
                            entries.pop_front();
                        } else {
                            entries[position].received = true;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
