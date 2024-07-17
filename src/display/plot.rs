use std::io::Write;

use crossterm::QueueableCommand;

use super::DisplayModeTrait;

pub struct HorizontalPlotDisplayMode {
    // columns: u16,
    position: usize,
    stdout: std::io::Stdout,
    row_front_sequence: Vec<usize>,
    colors: Vec<crossterm::style::Color>,
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
            colors: vec![crossterm::style::Color::Green, crossterm::style::Color::Blue],
            address_col: 2,
            graph_col: 4,
        }
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

    fn display_send(&mut self, index: usize, _target: &std::net::IpAddr, _length: usize, sequence: u64) -> std::io::Result<()> {
        let row = index;
        self.row_front_sequence[row] = sequence as usize;
        self.print(row, self.graph_col, "\x1b[@?", crossterm::style::Color::Yellow)?;
        Ok(())
    }

    fn display_receive(
        &mut self,
        _index: usize,
        sequence: u64,
        _response: &crate::ping::EchoReply,
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

    fn display_error(&mut self, index: usize, sequence: u64, _error: &crate::ping::RecvError) -> std::io::Result<()> {
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
