use super::DisplayModeTrait;

pub struct NoneDisplayMode;

impl DisplayModeTrait for NoneDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        NoneDisplayMode {}
    }
    fn display_send(&mut self, _index: usize, _target: &std::net::IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn display_receive(
        &mut self,
        _index: usize,
        _sequence: u64,
        _response: &crate::ping::EchoReply,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        Ok(())
    }

    fn display_timeout(&mut self, _index: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, _error: &crate::ping::RecvError) -> std::io::Result<()> {
        Ok(())
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
