use std::{collections::VecDeque, time::Duration};

use xping::PingEventHandler;

#[derive(Clone)]
pub struct Stats {
    index: u64,
    pub sent: u32,
    pub completed: u32,
    pub received: u32,
    cumulative_rtt: std::time::Duration,
}

impl Stats {
    fn new(index: u64) -> Self {
        Self {
            index,
            sent: 0,
            completed: 0,
            received: 0,
            cumulative_rtt: std::time::Duration::from_secs(0),
        }
    }

    fn add_received(&mut self, round_trip_time: Duration) {
        self.received += 1;
        self.completed += 1;
        self.cumulative_rtt += round_trip_time;
    }

    fn add_completed(&mut self) {
        self.completed += 1;
    }

    pub fn average_rtt(&self) -> Option<std::time::Duration> {
        if self.received > 0 {
            Some(self.cumulative_rtt / self.received)
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct StatsTable {
    /// Table of statistics for each bucket, added as they are started and
    /// removed as they are completed.
    table: VecDeque<Stats>,

    bucket_size: u64,
}

impl StatsTable {
    pub fn new(bucket_size: usize) -> Self {
        Self {
            table: VecDeque::default(),
            bucket_size: bucket_size as u64,
        }
    }

    /// Add a completed packet to the table
    fn on_completed(&mut self, sequence: u64) {
        let index = sequence / self.bucket_size;
        let table = &mut self.table;
        let delta_index = index.wrapping_sub(table.front().unwrap().index) as i64;
        if dbg!(delta_index) < 0 {
            // ignore, old data
        } else if delta_index < table.len() as i64 {
            table[delta_index as usize].add_completed();
        } else {
            // ignore, unexpected data
        }
    }

    pub fn pop_completed(&mut self) -> Option<Stats> {
        if self.table.is_empty() {
            None
        } else if self.table.front().unwrap().completed == (self.bucket_size as u32) {
            Some(self.table.pop_front().unwrap())
        } else {
            None
        }
    }
}

impl PingEventHandler for StatsTable {
    fn on_sent(&mut self, sequence: u64) {
        let index = sequence / self.bucket_size;
        if self.table.is_empty() || self.table.back().unwrap().index < index {
            let mut stats = Stats::new(index);
            stats.sent = 1;
            self.table.push_back(stats);
        } else {
            self.table.back_mut().unwrap().sent += 1;
        }
    }

    /// Add a received & completed packet to the table
    fn on_received(&mut self, sequence: u64, round_trip_time: Duration) {
        let index = sequence / self.bucket_size;
        let table = &mut self.table;
        let delta_index = index.wrapping_sub(table.front().unwrap().index) as i64;
        if delta_index < 0 {
            // ignore, old data
        } else if delta_index < table.len() as i64 {
            table[delta_index as usize].add_received(round_trip_time);
        } else {
            // ignore, unexpected data
        }
    }

    fn on_error(&mut self, sequence: u64) {
        self.on_completed(sequence);
    }

    fn on_timeout(&mut self, sequence: u64) {
        self.on_completed(sequence);
    }
}
