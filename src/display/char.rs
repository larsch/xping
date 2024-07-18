use std::io::Write;

use crossterm::QueueableCommand;

use crate::event_handler::{GenericResult, GlobalPingEventHandler};

use super::DisplayModeTrait;

pub struct CharDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

impl CharDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str, color: crossterm::style::Color) -> GenericResult {
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
        Ok(self.stdout.flush()?)
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

    fn close(&mut self) -> std::io::Result<()> {
        if self.position % self.columns != 0 {
            println!();
        }
        Ok(())
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}

impl GlobalPingEventHandler for CharDisplayMode {
    fn on_sent(&mut self, _target: usize, seq: u64, _length: usize) -> GenericResult {
        self.position = seq + 1;
        if seq % self.columns == self.columns - 1 {
            println!(".");
        } else {
            print!(".");
        }
        Ok(self.stdout.flush()?)
    }

    fn on_received(&mut self, _target: usize, seq: u64, _rtt: std::time::Duration) -> GenericResult {
        self.display_outcome(seq, "o", crossterm::style::Color::Green)?;
        Ok(())
    }

    fn on_error(&mut self, _target: usize, seq: u64, error: &crate::ping::RecvError) -> GenericResult {
        if let Some(code) = error.icmp_code {
            self.display_outcome(seq, &format!("{}", code), crossterm::style::Color::Red)
        } else {
            self.display_outcome(seq, "E", crossterm::style::Color::Red)
        }
    }

    fn on_timeout(&mut self, _target: usize, seq: u64) -> GenericResult {
        self.display_outcome(seq, "x", crossterm::style::Color::Red)
    }
}
