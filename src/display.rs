use std::{collections::HashMap, io::Write, net::IpAddr};

use crossterm::QueueableCommand;

use crate::ping::{IcmpPacket, RecvError};

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum DisplayMode {
    #[default]
    Classic,
    Char,
    Dumb,
    CharGraph,
    Debug,
}

impl std::fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait DisplayModeTrait {
    fn new(columns: u16, rows: u16) -> Self
    where
        Self: Sized;
    fn display_send(&mut self, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()>;
    fn display_receive(&mut self, sequence: u64, response: &IcmpPacket, round_trip_time: std::time::Duration) -> std::io::Result<()>;
    fn display_error(&mut self, sequence: u64, error: &RecvError) -> std::io::Result<()>;
    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()>;
    fn close(&mut self) -> std::io::Result<()>;
}

pub struct ClassicDisplayMode {
    position: u64,
    widths: HashMap<u64, usize>,
    stdout: std::io::Stdout,
}

impl ClassicDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str) -> std::io::Result<()> {
        let relative_sequence = self.position - sequence;
        let width = self.widths.remove(&sequence).unwrap();
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        self.stdout.queue(crossterm::cursor::MoveUp(relative_sequence as u16))?;
        self.stdout.queue(crossterm::cursor::MoveToColumn(width as u16 + 1))?;
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

    fn display_send(&mut self, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        let output = format!("{} bytes for {}: icmp_seq={}", length, target, sequence);
        self.widths.insert(sequence, output.len());
        println!("{}", output);
        self.position = sequence + 1;
        Ok(())
    }

    fn display_receive(&mut self, sequence: u64, packet: &IcmpPacket, round_trip_time: std::time::Duration) -> std::io::Result<()> {
        match &packet.message.icmp_type {
            crate::ping::IcmpType::EchoReply(_) => self.display_outcome(sequence, &format!("time={:?}", round_trip_time)),
            crate::ping::IcmpType::IPv4DestinationUnreachable(unreach) => self.display_outcome(
                sequence,
                &format!(
                    "Destination unreachable from {:?}, {}",
                    packet.addr,
                    crate::ping::ipv4unreach_to_string(unreach)
                ),
            ),
            crate::ping::IcmpType::IPv6DestinationUnreachable(unreach) => self.display_outcome(
                sequence,
                &format!(
                    "Destination unreachable from {:?}, {}",
                    packet.addr,
                    crate::ping::ipv6unreach_to_string(unreach)
                ),
            ),
            crate::ping::IcmpType::TimeExceeded => self.display_outcome(sequence, &format!("TTL expired from {:?}", packet.addr)),
        }
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "timeout")
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        self.display_outcome(sequence, &format!("{:?}", error))
    }
}

impl Drop for ClassicDisplayMode {
    fn drop(&mut self) {
        self.stdout.queue(crossterm::cursor::Show).unwrap();
    }
}

pub struct DumbDisplayMode;

impl DisplayModeTrait for DumbDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DumbDisplayMode {}
    }
    fn display_send(&mut self, target: &IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", _length, target, _sequence))
    }

    fn display_receive(&mut self, _sequence: u64, response: &IcmpPacket, _round_trip_time: std::time::Duration) -> std::io::Result<()> {
        print!("received response for sequence {} in {:?}", _sequence, _round_trip_time);
        if let Some(recvttl) = response.recvttl {
            print!(", recvttl={}", recvttl);
        }
        Ok(println!(""))
    }

    fn display_timeout(&mut self, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("timeout for sequence {}", _sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(println!("{:?}", error))
    }
}

pub struct CharDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

impl CharDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str, color: crossterm::style::Color) -> std::io::Result<()> {
        let current_row = self.position / self.columns;
        let target_row = sequence / self.columns;
        let current_col = self.position % self.columns;
        let target_col = sequence % self.columns;
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        if target_row < current_row {
            self.stdout.queue(crossterm::cursor::MoveUp((current_row - target_row) as u16))?;
        }
        #[allow(clippy::comparison_chain)]
        if target_col < current_col {
            self.stdout.queue(crossterm::cursor::MoveLeft((current_col - target_col) as u16))?;
        } else if target_col > current_col {
            self.stdout.queue(crossterm::cursor::MoveRight((target_col - current_col) as u16))?;
        }
        self.stdout.queue(crossterm::style::SetForegroundColor(color))?;
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
    fn display_send(&mut self, _target: &IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
        self.position = sequence + 1;
        if sequence % self.columns == self.columns - 1 {
            println!(".");
        } else {
            print!(".");
        }
        self.stdout.flush()
    }

    fn display_receive(&mut self, sequence: u64, response: &IcmpPacket, _round_trip_time: std::time::Duration) -> std::io::Result<()> {
        let char = match response.message.icmp_type {
            crate::ping::IcmpType::EchoReply(_) => "o",
            crate::ping::IcmpType::IPv4DestinationUnreachable(_) => "u",
            crate::ping::IcmpType::IPv6DestinationUnreachable(_) => "u",
            crate::ping::IcmpType::TimeExceeded => "t",
        };
        self.display_outcome(sequence, char, crossterm::style::Color::Green)?;
        Ok(())
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "x", crossterm::style::Color::Red)
    }

    fn close(&mut self) -> std::io::Result<()> {
        if self.position % self.columns != 0 {
            println!();
        }
        Ok(())
    }

    fn display_error(&mut self, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        if let Some(code) = error.icmp_code {
            self.display_outcome(sequence, &format!("{}", code), crossterm::style::Color::Red)
        } else {
            self.display_outcome(sequence, "E", crossterm::style::Color::Red)
        }
    }
}

pub struct CharGraphDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

const GRAPH_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

impl CharGraphDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str, color: crossterm::style::Color) -> std::io::Result<()> {
        let current_row = self.position / self.columns;
        let target_row = sequence / self.columns;
        let current_col = self.position % self.columns;
        let target_col = sequence % self.columns;
        // println!("{} {} {} {}", current_row, current_col, target_row, target_col);
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        if target_row < current_row {
            self.stdout.queue(crossterm::cursor::MoveUp((current_row - target_row) as u16))?;
        }
        #[allow(clippy::comparison_chain)]
        if target_col < current_col {
            self.stdout.queue(crossterm::cursor::MoveLeft((current_col - target_col) as u16))?;
        } else if target_col > current_col {
            self.stdout.queue(crossterm::cursor::MoveRight((target_col - current_col) as u16))?;
        }
        self.stdout.queue(crossterm::style::SetForegroundColor(color))?;
        self.stdout.write_all(outcome.as_bytes())?;
        self.stdout.queue(crossterm::style::ResetColor)?;
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}

impl DisplayModeTrait for CharGraphDisplayMode {
    fn new(columns: u16, _rows: u16) -> Self {
        CharGraphDisplayMode {
            columns: columns as u64,
            position: 0,
            stdout: std::io::stdout(),
        }
    }
    fn display_send(&mut self, _target: &IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
        self.position = sequence + 1;
        if sequence % self.columns == self.columns - 1 {
            println!(".");
        } else {
            print!(".");
        }
        self.stdout.flush()
    }

    fn display_receive(&mut self, sequence: u64, _response: &IcmpPacket, round_trip_time: std::time::Duration) -> std::io::Result<()> {
        let n = (round_trip_time.as_millis() as f64 + 1.0).ln().max(0.0) / 7.0 * (GRAPH_CHARS.len() - 1) as f64;
        let n = n as usize;

        // const step_size_millis: u128 = 20;
        // let n = (round_trip_time.as_millis() / (step_size_millis)) as usize;
        let n = n.min(GRAPH_CHARS.len() - 1);

        // let color = crossterm::style::Color::Rgb { r: sequence as u8, g: sequence as u8, b: sequence as u8 };

        // let color = match sequence % 3 {
        //     0 => crossterm::style::Color::Green,
        //     1 => crossterm::style::Color::Yellow,
        //     2 => crossterm::style::Color::Rgb { r: (), g: (), b: () },
        //     _ => crossterm::style::Color::White,
        // };

        let color = latency_to_color(round_trip_time);

        self.display_outcome(sequence, &GRAPH_CHARS[n].to_string(), color)
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "?", crossterm::style::Color::Red)
    }

    fn close(&mut self) -> std::io::Result<()> {
        if self.position % self.columns != 0 {
            println!();
        }
        Ok(())
    }

    fn display_error(&mut self, _sequence: u64, _error: &RecvError) -> std::io::Result<()> {
        todo!()
    }
}

pub struct DebugDisplayMode;

impl DisplayModeTrait for DebugDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DebugDisplayMode {}
    }
    fn display_send(&mut self, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", length, target, sequence))
    }

    fn display_receive(&mut self, sequence: u64, response: &IcmpPacket, round_trip_time: std::time::Duration) -> std::io::Result<()> {
        Ok(println!("seq={:?}, response={:?}, rtt={:?}", sequence, response, round_trip_time))
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        Ok(println!("seq={}, timeout", sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(println!("seq={}, error={:?}", sequence, error))
    }
}

fn latency_to_color(latency: std::time::Duration) -> crossterm::style::Color {
    let millis = latency.as_millis();
    let millis = millis.min(255);
    let log_millis = (millis as f64 + 1.0).ln() / 7.0 * 255.0;
    crossterm::style::Color::Rgb {
        r: log_millis as u8,
        g: 255 - log_millis as u8,
        b: 0,
    }
}
