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
        while row >= self.current_row {
            self.current_row += 1;
            self.widths.push_back(0);
            self.stdout.write_all(b"<insline>\n").unwrap();
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
        if old_width > 0 {
            self.stdout.queue(crossterm::cursor::MoveToColumn(old_width as u16))?;
        }
        // self.stdout.write_all(format!("up {}, right {}", delta_rows, old_width).as_bytes())?;
        self.stdout.write_all(text.as_bytes()).unwrap();
        self.stdout.queue(crossterm::cursor::RestorePosition)?;
        self.stdout.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_appendable_display() {
        let mut display = AppendableDisplay::new(25);
        display.create("0 Hello").unwrap();
        display.create("1 World").unwrap();
        display.create("2 Foo").unwrap();
        display.create("3 Bar").unwrap();
        display.append(0, ">0 Hello, World!").unwrap();
        display.append(1, ">1 Hello, World!").unwrap();
        display.append(2, ">2 Hello, World!").unwrap();
        display.append(3, ">3 Hello, World!").unwrap();
        display.append(4, ">4 Hello, World!").unwrap();
    }

    #[test]
    fn test_appendable_gap() {
        let mut display = AppendableDisplay::new(25);
        for i in 0..10 {
            display.create(&format!("{} Hello", i)).unwrap();
            display.append(i, &format!(">{} Hello, World!", i)).unwrap();
        }
        for i in 10..20 {
            display.create(&format!("{} Hello", i)).unwrap();
        }
        for i in 20..30 {
            display.create(&format!("{} Hello", i)).unwrap();
            display.append(i, &format!(">{} Hello, World!", i)).unwrap();
        }
    }
}
