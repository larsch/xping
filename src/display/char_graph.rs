use std::io::Write;

use crossterm::QueueableCommand;

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
        _response: &crate::ping::EchoReply,
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

    fn display_error(&mut self, _index: usize, _sequence: u64, _error: &crate::ping::RecvError) -> std::io::Result<()> {
        todo!()
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
