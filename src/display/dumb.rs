use super::DisplayModeTrait;

pub struct DumbDisplayMode;

impl DisplayModeTrait for DumbDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        DumbDisplayMode {}
    }
    fn display_send(&mut self, _index: usize, target: &std::net::IpAddr, _length: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("send {} bytes to {} with sequence {}", _length, target, _sequence))
    }

    fn display_receive(
        &mut self,
        _index: usize,
        _sequence: u64,
        response: &crate::ping::EchoReply,
        _round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        print!("received response for sequence {} in {:?}", _sequence, _round_trip_time);
        if let Some(recvttl) = response.recvttl {
            print!(", recvttl={}", recvttl);
        }
        Ok(println!())
    }

    fn display_timeout(&mut self, _index: usize, _sequence: u64) -> std::io::Result<()> {
        Ok(println!("timeout for sequence {}", _sequence))
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, _sequence: u64, error: &crate::ping::RecvError) -> std::io::Result<()> {
        Ok(println!("{:?}", error))
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
