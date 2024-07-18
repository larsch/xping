use std::net::IpAddr;

use crate::event_handler::GlobalPingEventHandler;

use super::DisplayModeTrait;

pub struct InfluxLineProtocolDisplayMode {
    targets: Vec<(IpAddr, String)>,
}

impl DisplayModeTrait for InfluxLineProtocolDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self
    where
        Self: Sized,
    {
        InfluxLineProtocolDisplayMode { targets: Vec::new() }
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        assert!(index == self.targets.len());
        self.targets.push((*target, hostname.to_string()));
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl GlobalPingEventHandler for InfluxLineProtocolDisplayMode {
    fn on_sent(&mut self, _target: usize, _seq: u64, _length: usize) -> crate::event_handler::GenericResult {
        Ok(())
    }

    fn on_received(&mut self, target: usize, _seq: u64, rtt: std::time::Duration) -> crate::event_handler::GenericResult {
        let hostname = &self.targets[target].1;
        let ip = &self.targets[target].0;
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!(
            "ping,host={},ip={} sent=1i,recv=1i,rtt={} {}",
            hostname,
            ip,
            rtt.as_secs_f64(),
            influx_timestamp
        );
        Ok(())
    }

    fn on_error(&mut self, _target: usize, _seq: u64, _error: &crate::ping::RecvError) -> crate::event_handler::GenericResult {
        Ok(())
    }

    fn on_timeout(&mut self, target: usize, _seq: u64) -> crate::event_handler::GenericResult {
        let hostname = &self.targets[target].1;
        let ip = &self.targets[target].0;
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!("ping,host={},ip={} sent=1i,recv=0i {}", hostname, ip, influx_timestamp);
        Ok(())
    }
}
