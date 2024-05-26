#![allow(dead_code)]
#![allow(unused_variables)]

mod args;
mod display;
mod ping;
mod summary;

use clap::Parser;

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use crate::display::DisplayModeTrait;

use crate::ping::IcmpApi;

#[cfg(debug_assertions)]
mod update_readme;

struct TargetInfo {
    address: IpAddr,
    hostname: String,
    packets_transmitted: u64,
    packets_received: u64,
    minimum_rtt: Option<Duration>,
    maximum_rtt: Option<Duration>,
    total_rtt: std::time::Duration,
    total_rtt_counted: u64,
}

impl TargetInfo {
    fn as_summary(&self, total_time: Duration) -> summary::Summary {
        summary::Summary {
            hostname: self.hostname.clone(),
            address: self.address,
            packets_transmitted: self.packets_transmitted,
            packets_received: self.packets_received,
            minimum_rtt: self.minimum_rtt,
            maximum_rtt: self.maximum_rtt,
            average_rtt: if self.total_rtt_counted > 0 {
                Some(self.total_rtt / self.total_rtt_counted as u32)
            } else {
                None
            },
            total_time,
        }
    }
}

fn lookup_host(host: &str, force_ip: &args::ForceIp) -> Option<IpAddr> {
    let target = dns_lookup::lookup_host(host).ok()?;
    let target = if force_ip.ipv4 {
        target.iter().find(|ip| ip.is_ipv4())
    } else if force_ip.ipv6 {
        target.iter().find(|ip| ip.is_ipv6())
    } else {
        target.first()
    };
    target.cloned()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let args = args::Args::parse();

    #[cfg(debug_assertions)]
    if args.update_readme {
        update_readme::update_readme();
        return Ok(());
    }

    let mut targets = Vec::new();

    for hostname in &args.target {
        if args.force_ip.all {
            let target = dns_lookup::lookup_host(hostname).ok();

            match target {
                Some(ips) => {
                    for ip in ips {
                        targets.push(TargetInfo {
                            hostname: hostname.clone(),
                            address: ip,
                            packets_transmitted: 0,
                            packets_received: 0,
                            minimum_rtt: None,
                            maximum_rtt: None,
                            total_rtt: std::time::Duration::from_secs(0),
                            total_rtt_counted: 0,
                        });
                    }
                }
                None => {
                    eprintln!("No address found for {}", hostname);
                    std::process::exit(1);
                }
            }
        } else {
            let target = lookup_host(hostname, &args.force_ip);

            match target {
                Some(ip) => {
                    targets.push(TargetInfo {
                        hostname: hostname.clone(),
                        address: ip,
                        packets_transmitted: 0,
                        packets_received: 0,
                        minimum_rtt: None,
                        maximum_rtt: None,
                        total_rtt: std::time::Duration::from_secs(0),
                        total_rtt_counted: 0,
                    });
                }
                None => {
                    let injection = match (args.force_ip.ipv4, args.force_ip.ipv6) {
                        (true, false) => " IPv4",
                        (false, true) => " IPv6",
                        _ => "",
                    };
                    eprintln!("No{} address found for {}", injection, hostname);
                    std::process::exit(1);
                }
            }
        }
    }

    let interval = match args.rate {
        Some(rate) => std::time::Duration::from_secs(1) / rate,
        None => std::time::Duration::from_millis(args.interval),
    } / targets.len() as u32;

    let target_indices: HashMap<IpAddr, usize> = targets.iter().enumerate().map(|(i, t)| (t.address, i)).collect();

    let mut next_send = std::time::Instant::now();
    let mut ping_protocol: Box<dyn ping::IcmpApi> = match args.api {
        args::Api::IcmpSocket => Box::new(ping::IcmpSocketApi::new()?),
        #[cfg(windows)]
        #[cfg(feature = "iphelper")]
        args::Api::Iphelper => Box::new(ping::IpHelperApi::new()?),
    };

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
        args::DisplayMode::Classic => Box::new(display::ClassicDisplayMode::new(columns, rows)),
        args::DisplayMode::Char => Box::new(display::CharDisplayMode::new(columns, rows)),
        args::DisplayMode::Dumb => Box::new(display::DumbDisplayMode::new(columns, rows)),
        args::DisplayMode::CharGraph => Box::new(display::CharGraphDisplayMode::new(columns, rows)),
        args::DisplayMode::Plot => Box::new(display::HorizontalPlotDisplayMode::new(columns, rows)),
        args::DisplayMode::Debug => Box::new(display::DebugDisplayMode::new(columns, rows)),
        args::DisplayMode::None => Box::new(display::NoneDisplayMode::new(columns, rows)),
        args::DisplayMode::Influx => Box::new(display::InfluxLineProtocolDisplayMode::new(columns, rows)),
    };

    for (index, target) in targets.iter().enumerate() {
        display_mode.add_target(index, &target.address, &target.hostname)?;
    }

    let icmp_timeout = std::time::Duration::from_millis(args.timeout);

    let start_time = Instant::now();

    let mut address_index_iter = (0..targets.len()).cycle();
    let target_count = targets.len();

    while attempts_left > 0 || !entries.is_empty() {
        if attempts_left > 0 {
            let address_index = address_index_iter.next().unwrap();
            let target = &mut targets[address_index];

            let timestamp = time_reference.elapsed().as_nanos() as u64;
            let icmp_sequence = sequence as u16;
            ping_protocol.send(target.address, args.length, icmp_sequence, timestamp).unwrap();
            target.packets_transmitted += 1;

            let display_sequence = sequence / target_count as u64;

            let index = sequence % target_count as u64;

            display_mode.display_send(index as usize, &target.address, args.length, display_sequence)?;

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
                    let index = entry.sequence % target_count as u64;
                    let display_sequence = entry.sequence / target_count as u64;
                    display_mode.display_timeout(index as usize, display_sequence)?;
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
                    let target_index = target_indices[&packet.addr.ip()];
                    let target = &mut targets[target_index];
                    target.packets_received += 1;

                    if let Some(tx_timestamp) = packet.message.timestamp {
                        let rx_timestamp = (packet.time - time_reference).as_nanos() as u64;

                        if tx_timestamp > rx_timestamp || entries.is_empty() {
                            println!(
                                "ignoring packet with tx_timestamp > rx_timestamp or no entries: tx_timestamp: {}, rx_timestamp: {}",
                                tx_timestamp, rx_timestamp
                            );
                            continue; // Ignore responses that were sent after the receive timestamp
                        }
                        let nanos = rx_timestamp - tx_timestamp;
                        let round_trip_time = std::time::Duration::from_nanos(nanos);
                        target.total_rtt += round_trip_time;
                        target.total_rtt_counted += 1;
                        target.minimum_rtt = Some(target.minimum_rtt.map_or(round_trip_time, |min| min.min(round_trip_time)));
                        target.maximum_rtt = Some(target.maximum_rtt.map_or(round_trip_time, |max| max.max(round_trip_time)));
                        let front_sequence = entries.front().unwrap().sequence;
                        let position = (packet.message.seq as usize + 65536 - front_sequence as usize) % 65536;
                        if position <= entries.len() {
                            let entry = &entries[position];
                            let display_sequence = entry.sequence / target_count as u64;
                            let index = entry.sequence % target_count as u64;
                            display_mode.display_receive(index as usize, display_sequence, &packet, round_trip_time)?;
                            if position == 0 {
                                entries.pop_front();
                            } else {
                                entries[position].received = true;
                            }
                        }
                    } else {
                        println!("no timestamp found in packet: {:?}", packet);
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
                            let display_sequence = entry.sequence / target_count as u64;
                            let row = entry.sequence % target_count as u64;
                            display_mode.display_error(row as usize, display_sequence, &error)?;
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

    let elapsed = start_time.elapsed();
    for target in &targets {
        let summary = target.as_summary(elapsed);
        match args.summary {
            args::SummaryFormat::Text => print!("{}", summary.as_text()?),
            args::SummaryFormat::Json => println!("{}", serde_json::to_string(&summary)?),
            args::SummaryFormat::Csv => print!("{}", summary.as_csv()?),
            args::SummaryFormat::None => (),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_host() {
        assert!(lookup_host(
            "localhost",
            &args::ForceIp {
                ipv4: false,
                ipv6: false,
                all: false
            }
        )
        .is_some());
        assert!(lookup_host(
            "localhost",
            &args::ForceIp {
                ipv4: true,
                ipv6: false,
                all: false
            }
        )
        .is_some());
        assert!(lookup_host(
            "localhost",
            &args::ForceIp {
                ipv4: true,
                ipv6: false,
                all: false
            }
        )
        .unwrap()
        .is_ipv4());
        #[cfg(not(target_os = "linux"))]
        assert!(lookup_host(
            "localhost",
            &args::ForceIp {
                ipv4: false,
                ipv6: true,
                all: false
            }
        )
        .is_some());
        #[cfg(not(target_os = "linux"))]
        assert!(lookup_host(
            "localhost",
            &args::ForceIp {
                ipv4: false,
                ipv6: true,
                all: false
            }
        )
        .unwrap()
        .is_ipv6());
    }

    #[test]
    fn test_lookup_host_no_address() {
        assert!(lookup_host(
            "nonexistent",
            &args::ForceIp {
                ipv4: false,
                ipv6: false,
                all: false
            }
        )
        .is_none());
    }
}
