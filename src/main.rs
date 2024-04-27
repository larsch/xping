mod ping;

use crossterm::QueueableCommand;

use std::{env, io::Write, net, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = env::args().nth(1).unwrap();
    let target = dns_lookup::lookup_host(&target).unwrap();
    let target = target.first().unwrap();
    let target_sa = match target {
        net::IpAddr::V4(v4addr) => net::SocketAddr::V4(net::SocketAddrV4::new(*v4addr, 58)),
        net::IpAddr::V6(v6addr) => net::SocketAddr::V6(net::SocketAddrV6::new(*v6addr, 58, 0, 0)),
    };

    let interval = std::time::Duration::from_millis(250);
    let mut next = std::time::Instant::now();
    let ping_protocol = ping::PingProtocol::new(target_sa).unwrap();

    let mut sequence = 0u16;

    let time_reference = Instant::now();

    let mut stdout = std::io::stdout();

    let target_str = target.to_string();

    loop {
        let timestamp = time_reference.elapsed().as_nanos() as u64;
        ping_protocol.send(sequence, timestamp).unwrap();
        println!("{}: icmp_seq={}", target_str, sequence);
        sequence += 1;
        next += interval;

        loop {
            let time_left = next - std::time::Instant::now();
            if time_left.is_zero() {
                break;
            }
            let response = ping_protocol.recv(time_left).unwrap();
            match response {
                Some((_addr, _identifier, rx_sequence, timestamp, rx_time)) => {
                    let nanos = (rx_time - time_reference).as_nanos() as u64 - timestamp;
                    let round_trip_time = std::time::Duration::from_nanos(nanos);
                    let relative_sequence = sequence - rx_sequence;
                    stdout.queue(crossterm::cursor::SavePosition)?;
                    stdout.queue(crossterm::cursor::MoveUp(relative_sequence))?;
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
                }
                None => break,
            }
        }
    }

    // Rest of the code...
}
