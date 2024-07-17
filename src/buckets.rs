use std::{collections::VecDeque, time::Duration};

use crate::event_handler::GenericResult;
use crate::event_handler::GlobalPingEventHandler;
use crate::event_handler::TargetPingEventHandler;

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
    fn on_completed(&mut self, sequence: u64) -> GenericResult {
        let index = sequence / self.bucket_size;
        let table = &mut self.table;
        let delta_index = index.wrapping_sub(table.front().unwrap().index) as i64;
        if delta_index < 0 {
            // ignore, old data
        } else if delta_index < table.len() as i64 {
            table[delta_index as usize].add_completed();
        } else {
            // ignore, unexpected data
        }
        Ok(())
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

impl TargetPingEventHandler for StatsTable {
    fn on_sent(&mut self, sequence: u64, _length: usize) -> GenericResult {
        let index = sequence / self.bucket_size;
        if self.table.is_empty() || self.table.back().unwrap().index < index {
            let mut stats = Stats::new(index);
            stats.sent = 1;
            self.table.push_back(stats);
        } else {
            self.table.back_mut().unwrap().sent += 1;
        }
        Ok(())
    }

    /// Add a received & completed packet to the table
    fn on_received(&mut self, sequence: u64, round_trip_time: Duration) -> GenericResult {
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
        Ok(())
    }

    fn on_error(&mut self, sequence: u64, _error: &crate::ping::RecvError) -> GenericResult {
        self.on_completed(sequence)
    }

    fn on_timeout(&mut self, sequence: u64) -> GenericResult {
        self.on_completed(sequence)
    }
}

pub struct Target {
    pub address: std::net::IpAddr,
    pub hostname: Option<String>,
}

pub struct BucketStacks {
    buckets: Vec<StatsTable>,
    targets: Vec<Target>,
}

impl BucketStacks {
    pub fn new(bucket_size: usize, targets: Vec<Target>) -> Self {
        Self {
            buckets: targets.iter().map(|_| StatsTable::new(bucket_size)).collect(),
            targets,
        }
    }

    fn target_seq(&self, seq: u64) -> u64 {
        seq / self.targets.len() as u64
    }

    pub fn check_completed(&mut self) {
        // Check for completed buckets
        for (index, stats) in self.buckets.iter_mut().enumerate() {
            while let Some(stats) = stats.pop_completed() {
                let average_rtt = stats.average_rtt();
                // println!("{}: sent={}, received={}, completed={}, avg_rtt={:?}", index, stats.sent, stats.received, stats.completed, average_rtt);
            }
        }
    }
}

impl GlobalPingEventHandler for BucketStacks {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> GenericResult {
        let seq = self.target_seq(seq);
        self.buckets[target].on_sent(seq, length)
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> GenericResult {
        let seq = self.target_seq(seq);
        self.buckets[target].on_received(seq, rtt)
    }

    fn on_error(&mut self, target: usize, seq: u64, error: &crate::ping::RecvError) -> GenericResult {
        let seq = self.target_seq(seq);
        self.buckets[target].on_error(seq, error)
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> GenericResult {
        let seq = self.target_seq(seq);
        self.buckets[target].on_timeout(seq)
    }
}
