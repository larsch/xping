use std::net::IpAddr;

use crate::ping::{EchoReply, RecvError};

use super::DisplayModeTrait;

pub struct DebugDisplayMode;

impl DisplayModeTrait for DebugDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DebugDisplayMode {}
    }
    fn display_send(&mut self, _index: usize, target: &IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", length, target, sequence))
    }

    fn display_receive(
        &mut self,
        _index: usize,
        sequence: u64,
        response: &EchoReply,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        Ok(println!("seq={:?}, response={:?}, rtt={:?}", sequence, response, round_trip_time))
    }

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        Ok(println!("seq={}, timeout", sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, sequence: u64, error: &RecvError) -> std::io::Result<()> {
        Ok(println!("seq={}, error={:?}", sequence, error))
    }

    fn add_target(&mut self, _index: usize, _target: &IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
