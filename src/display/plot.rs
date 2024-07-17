use std::io::Write;

use crossterm::QueueableCommand;

use crate::event_handler::GlobalPingEventHandler;

use super::DisplayModeTrait;

pub struct HorizontalPlotDisplayMode {
    position: usize,
    stdout: std::io::Stdout,
    row_front_sequence: Vec<usize>,
    address_col: usize,
    graph_col: usize,
}

const GRAPH_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

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
    fn new(_columns: u16, _rows: u16) -> Self
    where
        Self: Sized,
    {
        HorizontalPlotDisplayMode {
            // columns,
            position: 0,
            stdout: std::io::stdout(),
            row_front_sequence: Vec::new(),
            address_col: 2,
            graph_col: 4,
        }
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn add_target(&mut self, index: usize, target: &std::net::IpAddr, hostname: &str) -> std::io::Result<()> {
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
}

impl GlobalPingEventHandler for HorizontalPlotDisplayMode {
    fn on_sent(&mut self, target: usize, seq: u64, _length: usize) -> crate::event_handler::GenericResult {
        let row = target;
        self.row_front_sequence[row] = seq as usize / self.position;
        self.print(row, self.graph_col, "\x1b[@?", crossterm::style::Color::Yellow)?;
        Ok(())
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> crate::event_handler::GenericResult {
        let row = target;
        let target_seq = (seq as usize) / self.position;
        let col = self.graph_col + self.row_front_sequence[row] - target_seq;
        let char = latency_to_char(rtt);
        self.print(row, col, &char.to_string(), crossterm::style::Color::Green)?;
        Ok(())
    }

    fn on_error(&mut self, target: usize, seq: u64, _error: &crate::ping::RecvError) -> crate::event_handler::GenericResult {
        let row = target;
        let target_seq = (seq as usize) / self.position;
        let col = self.graph_col + self.row_front_sequence[row] - target_seq;
        self.print(row, col, "e", crossterm::style::Color::Magenta)?;
        Ok(())
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> crate::event_handler::GenericResult {
        let row = target;
        let target_seq = (seq as usize) / self.position;
        let col = self.graph_col + self.row_front_sequence[row] - target_seq;
        self.print(row, col, "x", crossterm::style::Color::Red)?;
        Ok(())
    }
}
