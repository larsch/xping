use super::{appendable::AppendableDisplay, DisplayModeTrait};

pub struct ClassicDisplayMode {
    display: AppendableDisplay,
}

impl DisplayModeTrait for ClassicDisplayMode {
    fn new(_columns: u16, _rows: u16) -> Self {
        ClassicDisplayMode {
            display: AppendableDisplay::new(_rows as usize),
        }
    }

    fn display_send(&mut self, _index: usize, target: &std::net::IpAddr, length: usize, sequence: u64) -> std::io::Result<()> {
        let output = format!("{} bytes for {}: icmp_seq={}", length, target, sequence);
        self.display.create(&output)
    }

    fn display_receive(
        &mut self,
        _index: usize,
        sequence: u64,
        packet: &crate::ping::EchoReply,
        round_trip_time: std::time::Duration,
    ) -> std::io::Result<()> {
        let row = sequence as usize;
        let output = match &packet.message.icmp_type {
            crate::ping::IcmpType::EchoReply(_) => format!("time={:?}", round_trip_time),
            crate::ping::IcmpType::IPv4DestinationUnreachable(unreach) => format!(
                "Destination unreachable from {:?}, {}",
                packet.addr,
                crate::ping::ipv4unreach_to_string(unreach)
            ),
            crate::ping::IcmpType::IPv6DestinationUnreachable(unreach) => format!(
                "Destination unreachable from {:?}, {}",
                packet.addr,
                crate::ping::ipv6unreach_to_string(unreach)
            ),
            crate::ping::IcmpType::TimeExceeded => format!("TTL expired from {:?}", packet.addr),
        };
        self.display.append(row, &output)
    }

    fn display_timeout(&mut self, _index: usize, sequence: u64) -> std::io::Result<()> {
        let row = sequence as usize;
        self.display.append(row, "timeout")
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn display_error(&mut self, _index: usize, sequence: u64, error: &crate::ping::RecvError) -> std::io::Result<()> {
        let row = sequence as usize;
        self.display.append(row, &format!("{:?}", error))
    }

    fn add_target(&mut self, _index: usize, _target: &std::net::IpAddr, _hostname: &str) -> std::io::Result<()> {
        Ok(())
    }
}
