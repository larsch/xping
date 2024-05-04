use std::{collections::HashMap, io::Write, net::IpAddr};

use crossterm::QueueableCommand;

use crate::ping::IcmpResponse;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum DisplayMode {
    #[default]
    Classic,
    Char,
    Dumb,
    CharGraph,
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
    fn display_send(
        &mut self,
        target: &IpAddr,
        length: usize,
        sequence: u64,
    ) -> std::io::Result<()>;
    fn display_receive(
        &mut self,
        sequence: u64,
        response: IcmpResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()>;
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
        self.stdout
            .queue(crossterm::cursor::MoveUp(relative_sequence as u16))?;
        self.stdout
            .queue(crossterm::cursor::MoveToColumn(width as u16 + 1))?;
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
        _response: IcmpResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        match _response.icmp_type {
            crate::ping::IcmpType::EchoReply(_) => {
                self.display_outcome(sequence, &format!("time={:?}", round_trip_time))
            }
            crate::ping::IcmpType::IPv4DestinationUnreachable(unreach) => self.display_outcome(
                sequence,
                &format!(
                    "Destination unreachable from {:?}, {}",
                    _response.addr,
                    crate::ping::ipv4unreach_to_string(unreach)
                ),
            ),
            crate::ping::IcmpType::IPv6DestinationUnreachable(unreach) => self.display_outcome(
                sequence,
                &format!(
                    "Destination unreachable from {:?}, {}",
                    _response.addr,
                    crate::ping::ipv6unreach_to_string(unreach)
                ),
            ),
        }
    }

    fn display_timeout(&mut self, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "timeout")
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct DumbDisplayMode;

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
        _response: IcmpResponse,
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

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct CharDisplayMode {
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
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        if target_row < current_row {
            self.stdout
                .queue(crossterm::cursor::MoveUp((current_row - target_row) as u16))?;
        }
        #[allow(clippy::comparison_chain)]
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
        _response: IcmpResponse,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        self.display_outcome(sequence, "o", crossterm::style::Color::Green)
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
}

pub struct CharGraphDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

const GRAPH_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

impl CharGraphDisplayMode {
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
        #[allow(clippy::comparison_chain)]
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

impl DisplayModeTrait for CharGraphDisplayMode {
    fn new(columns: u16, _rows: u16) -> Self {
        CharGraphDisplayMode {
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
        _response: IcmpResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let n = (round_trip_time.as_millis() as f64 + 1.0).ln().max(0.0) / 7.0
            * (GRAPH_CHARS.len() - 1) as f64;
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
