use std::net::IpAddr;

use crate::ping::RecvError;

use crate::event_handler::{GenericResult, GlobalPingEventHandler};

use super::DisplayModeTrait;

pub struct DebugDisplayMode;

impl DisplayModeTrait for DebugDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DebugDisplayMode {}
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(println!("close()"))
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        Ok(println!(
            "add_target(index={:?}, target={:?}, hostname={:?})",
            index, target, hostname
        ))
    }
}

impl GlobalPingEventHandler for DebugDisplayMode {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> GenericResult {
        Ok(println!("on_sent(target={:?}, seq={:?}, length={:?})", target, seq, length))
    }

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> GenericResult {
        Ok(println!("on_received(target={:?}, seq={:?}, rtt={:?})", target, seq, rtt))
    }

    fn on_error(&mut self, target: usize, seq: u64, error: &RecvError) -> GenericResult {
        Ok(println!("on_error(target={:?}, seq={:?}, error={:?})", target, seq, error))
    }

    fn on_timeout(&mut self, target: usize, seq: u64) -> GenericResult {
        Ok(println!("on_timeout(target={:?}, seq={:?})", target, seq))
    }
}
