use std::{collections::VecDeque, io::Write};

use crossterm::QueueableCommand;

/// A terminal display that can append text to existing rows.
pub struct AppendableDisplay {
    current_row: usize,
    max_rows: usize,
    widths: VecDeque<usize>,
    stdout: std::io::Stdout,
}

impl AppendableDisplay {
    pub fn new(max_rows: usize) -> Self {
        AppendableDisplay {
            current_row: 0,
            max_rows,
            widths: VecDeque::new(),
            stdout: std::io::stdout(),
        }
    }

    fn flush(&mut self) {
        while self.widths.len() >= self.max_rows {
            self.widths.pop_front();
        }
    }

    /// Create a new row with text.
    pub fn create(&mut self, text: &str) -> std::io::Result<()> {
        self.widths.push_back(text.len());
        self.stdout.write_all(text.as_bytes())?;
        self.stdout.write_all(b"\n")?;
        self.current_row += 1;
        self.flush();
        Ok(())
    }

    /// Append text to an existing row.
    ///
    /// If the row is above the maximum displayed rows (outside of screen), the
    /// text is discarded.
    pub fn append(&mut self, row: usize, text: &str) -> std::io::Result<()> {
        while row > self.current_row {
            self.current_row += 1;
            self.stdout.write_all(b"\n").unwrap();
        }
        self.flush();
        let delta_rows = self.current_row - row;
        if delta_rows > self.widths.len() {
            return Ok(());
        }
        let width = text.len();
        let width_index = self.widths.len() - delta_rows;
        let old_width = self.widths[width_index];
        self.widths[width_index] = old_width + width;

        self.stdout.queue(crossterm::cursor::SavePosition)?;
        self.stdout.queue(crossterm::cursor::MoveUp(delta_rows as u16))?;
        self.stdout.queue(crossterm::cursor::MoveToColumn(old_width as u16 + 1))?;
        self.stdout.write_all(text.as_bytes()).unwrap();
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}
