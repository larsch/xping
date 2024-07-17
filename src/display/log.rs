use std::net::IpAddr;

use crate::event_handler::GlobalPingEventHandler;

use super::DisplayModeTrait;

pub struct LogDisplay {
    targets: Vec<(IpAddr, String)>,
}

impl DisplayModeTrait for LogDisplay {
    fn new(_columns: u16, _rows: u16) -> Self {
        LogDisplay { targets: Vec::new() }
    }
    fn add_target(&mut self, index: usize, target: &std::net::IpAddr, hostname: &str) -> std::io::Result<()> {
        assert!(index == self.targets.len());
        self.targets.push((*target, hostname.to_string()));
        Ok(())
    }
    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl GlobalPingEventHandler for LogDisplay {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> crate::event_handler::GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("Sent {} bytes with sequence {} to {}", length, seq, target_addr))
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> crate::event_handler::GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("Received response from {} for sequence {} in {:?}", target_addr, seq, rtt))
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> crate::event_handler::GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("Timeout for sequence {} from {}", seq, target_addr))
    }

    fn on_error(&mut self, target: usize, seq: u64, error: &crate::ping::RecvError) -> crate::event_handler::GenericResult {
        let target_addr = self.targets[target].0;
        Ok(println!("Error for sequence {} from {}: {:?}", seq, target_addr, error))
    }
}
