#![allow(dead_code)]
#![allow(unused_variables)]

mod args;
mod buckets;
mod display;
mod duration;
mod event_handler;
mod ping;
mod summary;

use buckets::BucketStacks;
use clap::Parser;
use display::DisplayModeTrait;
use event_handler::GlobalPingEventHandler;
use ping::IcmpApi;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

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

    fn add_rtt(&mut self, round_trip_time: Duration) {
        self.total_rtt += round_trip_time;
        self.total_rtt_counted += 1;
        self.minimum_rtt = Some(self.minimum_rtt.map_or(round_trip_time, |min| min.min(round_trip_time)));
        self.maximum_rtt = Some(self.maximum_rtt.map_or(round_trip_time, |max| max.max(round_trip_time)));
    }
}

/// Information about a probe that has been sent
struct ProbeInfo {
    /// The sequence number of the probe
    sequence: u64,
    /// The time when the probe will time out
    timeout: std::time::Instant,
    /// The time when the probe was sent
    tx_timestamp: std::time::SystemTime,
    /// Whether the response has been received
    response_received: bool,
}

impl ProbeInfo {
    /// Calculate the round trip time based on the tx_timestamp and the rx_timestamp in the echo response
    fn os_timestamp_rtt(&self, echo_response: &ping::EchoReply) -> Option<std::time::Duration> {
        echo_response
            .socket_timestamp
            .map(|rx_timestamp| rx_timestamp.duration_since(self.tx_timestamp).unwrap())
    }

    fn local_rtt(&self, echo_response: &ping::EchoReply) -> Option<std::time::Duration> {
        echo_response
            .message
            .timestamp
            .map(|timestamp| echo_response.timestamp.duration_since(timestamp).unwrap())
    }

    /// Get the round-trip-time of the packet. This function will first try to
    /// calculate the RTT based on the OS timestamps and if that fails, it will
    /// try to calculate the RTT based on the local timestamps.
    fn rtt(&self, echo_response: &ping::EchoReply) -> Option<std::time::Duration> {
        self.os_timestamp_rtt(echo_response).or_else(|| self.local_rtt(echo_response))
    }
}

struct ProbeTable {
    table: VecDeque<ProbeInfo>,
}

impl ProbeTable {
    fn new() -> Self {
        Self { table: VecDeque::new() }
    }

    fn cleanup(&mut self) {
        // Remove all entries that have been received
        while !self.table.is_empty() && self.table.front().unwrap().response_received {
            self.table.pop_front();
        }
    }

    fn get(&mut self, sequence: u64) -> Option<&ProbeInfo> {
        if self.table.is_empty() {
            return None;
        }
        let front_sequence = self.table.front().unwrap().sequence;
        let position = (sequence as usize + 65536 - front_sequence as usize) % 65536;
        if position < self.table.len() {
            let probe_info = &mut self.table[position];
            probe_info.response_received = true;
            Some(probe_info)
        } else {
            None
        }
    }

    fn add(&mut self, probe: ProbeInfo) {
        self.table.push_back(probe);
    }

    fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    fn clear(&mut self) {
        self.table.clear();
    }

    fn pop_timeout(&mut self) -> Option<ProbeInfo> {
        self.cleanup();
        if self.table.is_empty() {
            None
        } else {
            let front = self.table.front().unwrap();
            if front.timeout <= std::time::Instant::now() {
                Some(self.table.pop_front().unwrap())
            } else {
                None
            }
        }
    }

    /// Get the time when the next probe will time out
    fn next_timeout(&self) -> Option<std::time::Instant> {
        self.table.front().map(|probe| probe.timeout)
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
    let (tx, interrupt_rx) = std::sync::mpsc::channel();
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

    let sample_size = match args.report_interval {
        Some(report_interval) => 1.max((report_interval * args.rate.unwrap_or(1) as f64).ceil() as usize),
        None => args.sample_size,
    };

    let target_indices: HashMap<IpAddr, usize> = targets.iter().enumerate().map(|(i, t)| (t.address, i)).collect();

    let mut next_send = std::time::Instant::now();
    let mut ping_protocol: Box<dyn ping::IcmpApi> = match args.api {
        args::Api::IcmpSocket => Box::new(ping::IcmpSocketApi::new()?),
        #[cfg(windows)]
        #[cfg(feature = "iphelper")]
        args::Api::Iphelper => Box::new(ping::IpHelperApi::new()?),
    };

    ping_protocol.set_ttl(args.ttl).expect("Failed to set TTL");

    // Global probe sequence number. Increments for each probe sent for each
    // target. Dividing by the number of targets will give the sequence number
    // for the target. Taking the modulo of the number of targets will give the
    // index of the target.
    let mut global_seq = 0u64;

    let mut probes_remaining = args.count.unwrap_or(u32::MAX);

    let (columns, rows) = match crossterm::terminal::size() {
        Ok((w, h)) => (w - 1, h),
        Err(_) => (78, 25),
    };

    // Table of active probes
    let mut probes = ProbeTable::new();

    let mut display_mode: Box<dyn DisplayModeTrait> = match args.display {
        args::DisplayMode::Classic => Box::new(display::ClassicDisplayMode::new(columns, rows)),
        args::DisplayMode::CharGraph => Box::new(display::CharGraphDisplayMode::new(columns, rows)),
        args::DisplayMode::Char => Box::new(display::CharDisplayMode::new(columns, rows)),
        // args::DisplayMode::Dumb => Box::new(display::DumbDisplayMode::new(columns, rows)),
        // args::DisplayMode::CharGraph => Box::new(display::CharGraphDisplayMode::new(columns, rows)),
        // args::DisplayMode::Plot => Box::new(display::HorizontalPlotDisplayMode::new(columns, rows)),
        args::DisplayMode::Debug => Box::new(display::DebugDisplayMode::new(columns, rows)),
        args::DisplayMode::None => Box::new(display::NoneDisplayMode::new(columns, rows)),
        args::DisplayMode::Plot => Box::new(display::HorizontalPlotDisplayMode::new(columns, rows)),
        args::DisplayMode::Log => Box::new(display::LogDisplay::new(columns, rows)),
        args::DisplayMode::Influx => Box::new(display::InfluxLineProtocolDisplayMode::new(columns, rows)),
    };

    for (index, target) in targets.iter().enumerate() {
        display_mode.add_target(index, &target.address, &target.hostname)?;
    }

    let icmp_timeout = std::time::Duration::from_millis(args.timeout);

    let start_time = Instant::now();

    let mut address_index_iter = (0..targets.len()).cycle();
    let target_count = targets.len();

    // let mut stats = vec![StatsTable::new(sample_size); targets.len()];

    let target_targets = targets
        .iter()
        .map(|t| buckets::Target {
            address: t.address,
            hostname: Some(t.hostname.clone()),
        })
        .collect();

    let mut bucket_stacks = BucketStacks::new(sample_size, target_targets);

    while probes_remaining > 0 || !probes.is_empty() {
        // check if we need to send a new probe
        if probes_remaining > 0 && (next_send - std::time::Instant::now()).is_zero() {
            let target_index = address_index_iter.next().unwrap();
            let target = &mut targets[target_index];

            let icmp_seq = global_seq as u16;
            let tx_timestamp = ping_protocol.send(target.address, args.length, icmp_seq).unwrap();

            bucket_stacks.on_sent(target_index, global_seq, args.length)?;
            display_mode.on_sent(target_index, global_seq, args.length)?;

            probes.add(ProbeInfo {
                sequence: global_seq,
                timeout: std::time::Instant::now() + icmp_timeout,
                tx_timestamp,
                response_received: false,
            });

            target.packets_transmitted += 1;
            probes_remaining -= 1;
            global_seq += 1;
            next_send += interval;
        }

        if let Ok(()) = interrupt_rx.try_recv() {
            if probes_remaining > 0 {
                // Cancel all remaining probes
                probes_remaining = 0;
            } else {
                // Exit immediately
                probes.clear();
                break;
            }
        }

        // Check for timeouts
        while let Some(probe) = probes.pop_timeout() {
            let index = (probe.sequence as usize) % target_count;
            display_mode.on_timeout(index, probe.sequence)?;

            bucket_stacks.on_timeout(index, global_seq)?;
            // stats[index as usize].on_timeout(display_sequence);
        }

        bucket_stacks.check_completed();

        // End receive loop if no more probes are active
        if probes.is_empty() && probes_remaining == 0 {
            break;
        }

        // Determine how long to wait until the next event
        let wait_until = if probes_remaining > 0 {
            if let Some(timeout) = probes.next_timeout() {
                next_send.min(timeout) // Wait for next timeout or next send
            } else {
                next_send // Wait for next send
            }
        } else if let Some(timeout) = probes.next_timeout() {
            timeout // Wait for next timeout
        } else {
            break; // No more active probes
        };

        let time_left = wait_until - std::time::Instant::now();

        // Ensure that Ctrl-C is responsive
        let time_left = time_left.min(Duration::from_millis(50));

        let result = ping_protocol.recv(time_left)?;
        match result {
            ping::RecvResult::EchoReply(packet) => {
                let target_index = target_indices[&packet.addr.ip()];
                let target = &mut targets[target_index];
                target.packets_received += 1;

                if probes.is_empty() {
                    continue;
                }

                if let Some(probe) = probes.get(packet.message.seq as u64) {
                    let round_trip_time = probe.rtt(&packet).unwrap();
                    target.add_rtt(round_trip_time);

                    let index = probe.sequence % target_count as u64;

                    bucket_stacks.on_received(target_index, probe.sequence, round_trip_time)?;
                    // let count_received = stats[target_index].on_received(display_sequence, round_trip_time);

                    display_mode.on_received(index as usize, probe.sequence, round_trip_time)?;
                }
            }
            ping::RecvResult::RecvError(error) => {
                if probes.is_empty() {
                    continue;
                }
                if let Some(orig_message) = &error.original_message {
                    if let Some(probe) = probes.get(orig_message.seq as u64) {
                        let target_index = probe.sequence % target_count as u64;
                        display_mode.on_error(target_index as usize, global_seq, &error)?;
                        bucket_stacks.on_error(target_index as usize, global_seq, &error)?;
                    }
                }
            }
            ping::RecvResult::RecvTimeout => {
                // timeout while waiting for response, just let loop
                // continue
            }
            ping::RecvResult::Interrupted => {
                // Interrupted by Ctrl-C, let loop continue (handled at
                // start of loop)
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
