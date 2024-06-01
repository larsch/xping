#![allow(unused_variables)]

use std::{collections::HashMap, io::Write, net::IpAddr};

use crossterm::QueueableCommand;

use crate::ping::{IcmpEchoResponse, RecvError};

pub trait DisplayModeTrait {
    fn new(columns: u16, rows: u16) -> Self
    where
        Self: Sized;
    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()>;
    fn display_send(&mut self, index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()>;
    fn display_receive(
        &mut self,
        index: usize,
        sequence: u64,
        response: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()>;
    fn display_error(&mut self, index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()>;
    fn display_timeout(&mut self, index: usize, sequence: u64) -> std::io::Result<()>;
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

    fn display_send(&mut self, _index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        let output = format!("{} bytes for {}: icmp_seq={}", length, target, sequence);
        self.widths.insert(sequence, output.len());
        println!("{}", output);
        self.position = sequence + 1;
        Ok(())
    }

    fn display_receive(
        &mut self,
        index: usize,
        sequence: u64,
        packet: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
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

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "timeout")
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        self.display_outcome(sequence, &format!("{:?}", error))
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
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
    fn display_send(&mut self, _index: usize, target: &IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", _length, target, _sequence))
    }

    fn display_receive(
        &mut self,
        _index: usize,
        _sequence: u64,
        response: &IcmpEchoResponse,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        print!("received response for sequence {} in {:?}", _sequence, _round_trip_time);
        if let Some(recvttl) = response.recvttl {
            print!(", recvttl={}", recvttl);
        }
        Ok(println!())
    }

    fn display_timeout(&mut self, _index: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("timeout for sequence {}", _sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(println!("{:?}", error))
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
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
    fn display_send(&mut self, _index: usize, _target: &IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
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
        _index: usize,
        sequence: u64,
        response: &IcmpEchoResponse,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let char = match response.message.icmp_type {
            crate::ping::IcmpType::EchoReply(_) => "o",
            crate::ping::IcmpType::IPv4DestinationUnreachable(_) => "u",
            crate::ping::IcmpType::IPv6DestinationUnreachable(_) => "u",
            crate::ping::IcmpType::TimeExceeded => "t",
        };
        self.display_outcome(sequence, char, crossterm::style::Color::Green)?;
        Ok(())
    }

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "x", crossterm::style::Color::Red)
    }

    fn close(&mut self) -> std::io::Result<()> {
        if self.position % self.columns != 0 {
            println!();
        }
        Ok(())
    }

    fn display_error(&mut self, _index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        if let Some(code) = error.icmp_code {
            self.display_outcome(sequence, &format!("{}", code), crossterm::style::Color::Red)
        } else {
            self.display_outcome(sequence, "E", crossterm::style::Color::Red)
        }
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
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
    fn display_send(&mut self, _index: usize, _target: &IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
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
        _index: usize,
        sequence: u64,
        _response: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
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

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        self.display_outcome(sequence, "?", crossterm::style::Color::Red)
    }

    fn close(&mut self) -> std::io::Result<()> {
        if self.position % self.columns != 0 {
            println!();
        }
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, _error: &RecvError) -> std::io::Result<()> {
        todo!()
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct DebugDisplayMode;

impl DisplayModeTrait for DebugDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DebugDisplayMode {}
    }
    fn display_send(&mut self, _index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", length, target, sequence))
    }

    fn display_receive(
        &mut self,
        _index: usize,
        sequence: u64,
        response: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        Ok(println!("seq={:?}, response={:?}, rtt={:?}", sequence, response, round_trip_time))
    }

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        Ok(println!("seq={}, timeout", sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(println!("seq={}, error={:?}", sequence, error))
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
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

pub struct NoneDisplayMode;

impl DisplayModeTrait for NoneDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        NoneDisplayMode {}
    }
    fn display_send(&mut self, _index: usize, _target: &IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn display_receive(
        &mut self,
        _index: usize,
        _sequence: u64,
        _response: &IcmpEchoResponse,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn display_timeout(&mut self, _index: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, _error: &RecvError) -> std::io::Result<()> {
        Ok(())
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct HorizontalPlotDisplayMode {
    columns: u16,
    position: usize,
    stdout: std::io::Stdout,
    row_front_sequence: Vec<usize>,
    colors: Vec<crossterm::style::Color>,
    address_col: usize,
    graph_col: usize,
}

fn latency_to_char(latency: std::time::Duration) -> char {
    let millis = latency.as_nanos() as f64 / 1_000_000.0;
    let n = ((millis + 1.0).ln().max(0.0) * 1.5) as usize;
    let n = n.min(GRAPH_CHARS.len() - 1);
    GRAPH_CHARS[n]
}

impl HorizontalPlotDisplayMode {
    fn adjust_hostname_col(&mut self, width: usize) -> std::io::Result<()> {
        let min_address_col = self.address_col.max(width + 2);
        if min_address_col > self.address_col {
            let shift = min_address_col - self.address_col;
            for row in 0..self.position {
                self.print(row, self.address_col, &format!("\x1b[{}@", shift), crossterm::style::Color::Black)?;
            }
            self.address_col = min_address_col;
            self.graph_col += shift;
        }
        Ok(())
    }

    fn adjust_address_col(&mut self, width: usize) -> std::io::Result<()> {
        let min_graph_col = self.graph_col.max(self.address_col + width + 2);
        if min_graph_col > self.graph_col {
            let shift = min_graph_col - self.graph_col;
            for row in 0..self.position {
                self.print(row, self.graph_col, &format!("\x1b[{}@", shift), crossterm::style::Color::Black)?;
            }
            self.graph_col = min_graph_col;
        }
        Ok(())
    }

    fn print(&mut self, row: usize, col: usize, text: &str, color: crossterm::style::Color) -> std::io::Result<()> {
        self.stdout.queue(crossterm::cursor::SavePosition)?;
        let delta_row = self.position - row;
        let delta_col = col;
        if delta_row > 0 {
            self.stdout.queue(crossterm::cursor::MoveUp(delta_row as u16))?;
        }
        if delta_col > 0 {
            self.stdout.queue(crossterm::cursor::MoveRight(delta_col as u16))?;
        }
        self.stdout.queue(crossterm::style::SetForegroundColor(color))?;
        self.stdout.write_all(text.as_bytes())?;
        self.stdout.queue(crossterm::style::ResetColor)?;
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}

impl DisplayModeTrait for HorizontalPlotDisplayMode {
    fn new(columns: u16, _rows: u16) -> Self
    where
        Self: Sized,
    {
        HorizontalPlotDisplayMode {
            columns,
            position: 0,
            stdout: std::io::stdout(),
            row_front_sequence: Vec::new(),
            colors: vec![crossterm::style::Color::Green, crossterm::style::Color::Blue],
            address_col: 2,
            graph_col: 4,
        }
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        while index > self.position {
            println!();
            self.position += 1;
        }
        if index == self.position {
            self.adjust_hostname_col(hostname.len())?;
            let target = format!("{}", target);
            self.adjust_address_col(target.len())?;
            println!("{}", hostname);
            self.position += 1;
            self.print(index, self.address_col, &target, crossterm::style::Color::White)?;
            self.row_front_sequence.resize(self.position, 0);
        }
        Ok(())
    }

    fn display_send(&mut self, index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        let row = index;
        self.row_front_sequence[row] = sequence as usize;
        self.print(row, self.graph_col, "\x1b[@?", crossterm::style::Color::Yellow)?;
        Ok(())
    }

    fn display_receive(
        &mut self,
        _index: usize,
        sequence: u64,
        response: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let row = _index;
        let col = self.graph_col + self.row_front_sequence[row] - sequence as usize;
        self.print(
            row,
            col,
            &latency_to_char(round_trip_time).to_string(),
            self.colors[row % self.colors.len()],
        )?;
        Ok(())
    }

    fn display_error(&mut self, index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        let row = index;
        let col = self.graph_col + self.row_front_sequence[row] - sequence as usize;
        self.print(row, col, "e", crossterm::style::Color::Red)?;
        Ok(())
    }

    fn display_timeout(&mut self, index: usize, sequence: u64) -> std::io::Result<()> {
        let row = index;
        let col = self.graph_col + self.row_front_sequence[row] - sequence as usize;
        self.print(row, col, "x", crossterm::style::Color::Red)?;
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct InfluxLineProtocolDisplayMode {
    hostnames: HashMap<usize, String>,
    addresses: HashMap<usize, IpAddr>,
}

impl DisplayModeTrait for InfluxLineProtocolDisplayMode {
    fn new(columns: u16, rows: u16) -> Self
    where
        Self: Sized,
    {
        InfluxLineProtocolDisplayMode {
            hostnames: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        self.hostnames.insert(index, hostname.to_string());
        self.addresses.insert(index, *target);
        Ok(())
    }

    fn display_send(&mut self, index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn display_receive(
        &mut self,
        index: usize,
        sequence: u64,
        response: &IcmpEchoResponse,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!(
            "ping,host={},ip={} sent=1i,recv=1i,rtt={} {}",
            self.hostnames[&index],
            response.addr.ip(),
            round_trip_time.as_secs_f64(),
            influx_timestamp
        );
        Ok(())
    }

    fn display_error(&mut self, index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(())
    }

    fn display_timeout(&mut self, index: usize, sequence: u64) -> std::io::Result<()> {
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!(
            "ping,host={},ip={} sent=1i,recv=0i {}",
            self.hostnames[&index], self.addresses[&index], influx_timestamp
        );
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
