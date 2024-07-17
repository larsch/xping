use std::io::Write;

use crossterm::QueueableCommand;

use crate::event_handler::{GenericResult, GlobalPingEventHandler};

use super::DisplayModeTrait;

pub struct CharGraphDisplayMode {
    columns: u64,
    position: u64,
    stdout: std::io::Stdout,
}

const GRAPH_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

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

impl CharGraphDisplayMode {
    fn display_outcome(&mut self, sequence: u64, outcome: &str, color: crossterm::style::Color) -> GenericResult {
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
        self.stdout.flush()?;
        Ok(())
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

impl GlobalPingEventHandler for CharGraphDisplayMode {
    fn on_sent(&mut self, _target: usize, seq: u64, _length: usize) -> GenericResult {
        self.position = seq + 1;
        if seq % self.columns == self.columns - 1 {
            println!(".");
        } else {
            print!(".");
        }
        Ok(self.stdout.flush()?)
    }

    fn on_received(&mut self, _target: usize, seq: u64, rtt: std::time::Duration) -> GenericResult {
        let n = (rtt.as_millis() as f64 + 1.0).ln().max(0.0) / 7.0 * (GRAPH_CHARS.len() - 1) as f64;
        let n = n as usize;
        let n = n.min(GRAPH_CHARS.len() - 1);
        let color = latency_to_color(rtt);
        self.display_outcome(seq, &GRAPH_CHARS[n].to_string(), color)
    }

    fn on_error(&mut self, _target: usize, seq: u64, _error: &crate::ping::RecvError) -> GenericResult {
        self.display_outcome(seq, "e", crossterm::style::Color::Magenta)
    }

    fn on_timeout(&mut self, _target: usize, seq: u64) -> GenericResult {
        self.display_outcome(seq, "?", crossterm::style::Color::Red)
    }
}
