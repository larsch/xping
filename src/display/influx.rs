use std::{collections::HashMap, net::IpAddr};

use super::DisplayModeTrait;

pub struct InfluxLineProtocolDisplayMode {
    hostnames: HashMap<usize, String>,
    addresses: HashMap<usize, IpAddr>,
}

impl DisplayModeTrait for InfluxLineProtocolDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self
    where
        Self: Sized,
    {
        InfluxLineProtocolDisplayMode {
            hostnames: HashMap::new(),
            addresses: HashMap::new(),
        }
    }

    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()> {
        self.hostnames.insert(index, hostname.to_string());
        self.addresses.insert(index, *target);
        Ok(())
    }

    fn display_send(&mut self, _index: usize, _target: &IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn display_receive(
        &mut self,
        index: usize,
        _sequence: u64,
        response: &crate::ping::EchoReply,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!(
            "ping,host={},ip={} sent=1i,recv=1i,rtt={} {}",
            self.hostnames[&index],
            response.addr.ip(),
            round_trip_time.as_secs_f64(),
            influx_timestamp
        );
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, _error: &crate::ping::RecvError) -> std::io::Result<()> {
        Ok(())
    }

    fn display_timeout(&mut self, index: usize, _sequence: u64) -> std::io::Result<()> {
        let influx_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        println!(
            "ping,host={},ip={} sent=1i,recv=0i {}",
            self.hostnames[&index], self.addresses[&index], influx_timestamp
        );
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
