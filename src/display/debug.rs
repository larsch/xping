use std::net::IpAddr;

use crate::ping::RecvError;

use crate::event_handler::{GenericResult, GlobalPingEventHandler};

use super::DisplayModeTrait;

pub struct DebugDisplayMode {
    targets: Vec<(IpAddr, String)>,
}

impl DisplayModeTrait for DebugDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DebugDisplayMode { targets: Vec::new() }
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        assert!(index == self.targets.len());
        self.targets.push((*target, hostname.to_string()));
        Ok(())
    }
}

impl GlobalPingEventHandler for DebugDisplayMode {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("send {} bytes to {} with sequence {}", length, target_addr, seq))
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("received response from {} for sequence {} in {:?}", target_addr, seq, rtt))
    }

    fn on_error(&mut self, target: usize, seq: u64, error: &RecvError) -> GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("error occured for sequence {} for {}: {:?}", seq, target_addr, error))
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("timeout for sequence {} for {}", seq, target_addr))
    }
}
