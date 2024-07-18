use crate::event_handler::GlobalPingEventHandler;

use super::DisplayModeTrait;

pub struct NoneDisplayMode;

impl DisplayModeTrait for NoneDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        NoneDisplayMode {}
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl GlobalPingEventHandler for NoneDisplayMode {
    fn on_sent(&mut self, _target: usize, _seq: u64, _length: usize) -> crate::event_handler::GenericResult {
        Ok(())
    }

    fn on_received(&mut self, _target: usize, _seq: u64, _rtt: std::time::Duration) -> crate::event_handler::GenericResult {
        Ok(())
    }

    fn on_timeout(&mut self, _target: usize, _seq: u64) -> crate::event_handler::GenericResult {
        Ok(())
    }

    fn on_error(&mut self, _target: usize, _seq: u64, _error: &crate::ping::RecvError) -> crate::event_handler::GenericResult {
        Ok(())
    }
}
