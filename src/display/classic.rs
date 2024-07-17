use std::net::IpAddr;

use crate::event_handler::GlobalPingEventHandler;

use super::{appendable::AppendableDisplay, DisplayModeTrait};

pub struct ClassicDisplayMode {
    display: AppendableDisplay,
    targets: Vec<(IpAddr, String)>,
}

impl DisplayModeTrait for ClassicDisplayMode {
    fn new(_columns: u16, rows: u16) -> Self
    where
        Self: Sized,
    {
        ClassicDisplayMode {
            display: AppendableDisplay::new(rows as usize),
            targets: Vec::new(),
        }
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

impl GlobalPingEventHandler for ClassicDisplayMode {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> crate::event_handler::GenericResult {
        let target = self.targets[target].0;
        let output = format!("{} bytes for {}: icmp_seq={}", length, target, seq);
        Ok(self.display.create(&output)?)
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> crate::event_handler::GenericResult {
        let output = format!("time={:?}", rtt);
        Ok(self.display.append(seq as usize, &output)?)
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> crate::event_handler::GenericResult {
        Ok(self.display.append(seq as usize, "timeout")?)
    }

    fn on_error(&mut self, target: usize, seq: u64, error: &crate::ping::RecvError) -> crate::event_handler::GenericResult {
        Ok(self.display.append(seq as usize, &format!("{:?}", error))?)
    }
}
