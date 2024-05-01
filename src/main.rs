mod ping;

use clap::Parser;
use crossterm::QueueableCommand;
use std::{
    collections::{HashMap, VecDeque},
    fmt::{self, Display},
    io::Write,
    net::{self, IpAddr},
    time::Instant,
};

#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum DisplayMode {
    #[default]
    Classic,
    Char,
    Dumb,
}

impl Display for DisplayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

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
    display: DisplayMode,
}

trait DisplayModeTrait {
    fn new(columns: u16, rows: u16) -> Self
    where
        Self: Sized;
    fn display_send(
        &mut self,
        target: &IpAddr,
        length: usize,
        sequence: u64,
    ) -> std::io::Result<()>;
    fn display_receive(
        &mut self,
        sequence: u64,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()>;
    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()>;
}

struct ClassicDisplayMode {
    position: u64,
    widths: HashMap<u64, usize>,
    stdout: std::io::Stdout,
}

impl ClassicDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str) -> std::io::Result<()> {
        let relative_sequence = self.position - sequence;
        let width = self.widths.remove(&sequence).unwrap();
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        self.stdout
            .queue(crossterm::cursor::MoveUp(relative_sequence as u16))?;
        self.stdout
            .queue(crossterm::cursor::MoveRight(width as u16 + 1))?;
        print!("{}", outcome);
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}

impl DisplayModeTrait for ClassicDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        ClassicDisplayMode {
            position: 0,
            widths: HashMap::new(),
            stdout: std::io::stdout(),
        }
    }

    fn display_send(
        &mut self,
        target: &IpAddr,
        length: usize,
        sequence: u64,
    ) -> std::io::Result<()> {
        let output = format!("{} bytes for {}: icmp_seq={}", length, target, sequence);
        self.widths.insert(sequence, output.len());
        println!("{}", output);
        self.position = sequence + 1;
        Ok(())
    }

    fn display_receive(
        &mut self,
        sequence: u64,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        self.display_outcome(sequence, &format!("time={:?}", round_trip_time))
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "timeout")
    }
}

struct DumbDisplayMode;

impl DisplayModeTrait for DumbDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DumbDisplayMode {}
    }
    fn display_send(
        &mut self,
        target: &IpAddr,
        _length: usize,
        _sequence: u64,
    ) -> std::io::Result<()> {
        Ok(println!(
            "send {} bytes to {} with sequence {}",
            _length, target, _sequence
        ))
    }

    fn display_receive(
        &mut self,
        _sequence: u64,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        Ok(println!(
            "received response for sequence {} in {:?}",
            _sequence, _round_trip_time
        ))
    }

    fn display_timeout(&mut self, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("timeout for sequence {}", _sequence))
    }
}

struct CharDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

impl CharDisplayMode {
    fn display_outcome(
        &mut self,
        sequence: u64,
        outcome: &str,
        color: crossterm::style::Color,
    ) -> std::io::Result<()> {
        let current_row = self.position / self.columns;
        let target_row = sequence / self.columns;
        let current_col = self.position % self.columns;
        let target_col = sequence % self.columns;
        // println!("{} {} {} {}", current_row, current_col, target_row, target_col);
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        if target_row < current_row {
            self.stdout
                .queue(crossterm::cursor::MoveUp((current_row - target_row) as u16))?;
        }
        if target_col < current_col {
            self.stdout.queue(crossterm::cursor::MoveLeft(
                (current_col - target_col) as u16,
            ))?;
        } else if target_col > current_col {
            self.stdout.queue(crossterm::cursor::MoveRight(
                (target_col - current_col) as u16,
            ))?;
        }
        self.stdout
            .queue(crossterm::style::SetForegroundColor(color))?;
        self.stdout.write_all(outcome.as_bytes())?;
        self.stdout.queue(crossterm::style::ResetColor)?;
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}

impl DisplayModeTrait for CharDisplayMode {
    fn new(columns: u16, _rows: u16) -> Self {
        CharDisplayMode {
            columns: columns as u64,
            position: 0,
            stdout: std::io::stdout(),
        }
    }
    fn display_send(
        &mut self,
        _target: &IpAddr,
        _length: usize,
        sequence: u64,
    ) -> std::io::Result<()> {
        self.position = sequence + 1;
        if sequence % self.columns == self.columns - 1 {
            println!(".");
        } else {
            print!(".");
        }
        self.stdout.flush()
    }

    fn display_receive(
        &mut self,
        sequence: u64,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        self.display_outcome(sequence, "o", crossterm::style::Color::Green)
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "x", crossterm::style::Color::Red)
    }
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

    let mut display_mode: Box<dyn DisplayModeTrait> = match args.display {
        DisplayMode::Classic => Box::new(ClassicDisplayMode::new(columns, rows)),
        DisplayMode::Char => Box::new(CharDisplayMode::new(columns, rows)),
        DisplayMode::Dumb => Box::new(DumbDisplayMode::new(columns, rows)),
    };

    while attempts_left > 0 || !entries.is_empty() {
        if attempts_left > 0 {
            let timestamp = time_reference.elapsed().as_nanos() as u64;
            let icmp_sequence = sequence as u16;
            ping_protocol.send(icmp_sequence, timestamp).unwrap();

            display_mode.display_send(target, args.length, sequence)?;

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
                    display_mode.display_timeout(entry.sequence)?;
                    entries.pop_front();
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
        }
    }
    Ok(())
}
