use std::io::Write;

use crossterm::QueueableCommand;

use super::DisplayModeTrait;

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
    fn display_send(&mut self, _index: usize, _target: &std::net::IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
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
        response: &crate::ping::EchoReply,
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

    fn display_error(&mut self, _index: usize, sequence: u64, error: &crate::ping::RecvError) -> std::io::Result<()> {
        if let Some(code) = error.icmp_code {
            self.display_outcome(sequence, &format!("{}", code), crossterm::style::Color::Red)
        } else {
            self.display_outcome(sequence, "E", crossterm::style::Color::Red)
        }
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
