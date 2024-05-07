mod sockaddr;

#[cfg(target_os = "linux")]
mod linux;

use std::{fmt::Display, net::SocketAddr};

#[cfg(target_os = "linux")]
pub use linux::PingProtocol;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::PingProtocol;

pub trait Pinger {
    fn new(target: std::net::SocketAddr, length: usize) -> Result<Self, std::io::Error>
    where
        Self: Sized;

    /// Set the TTL (time-to-live) of ICMP packets sent using the send() method.
    fn set_ttl(&mut self, ttl: u8) -> Result<(), std::io::Error>;

    /// Send an ICMP packet with the given sequence number and timestamp. The
    /// timestamp is inserted into the ICMP payload and can be used to calculate
    /// the round-trip time.
    fn send(&mut self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error>;

    /// Wait for the next ICMP packet, error, or timeout. Returns the received
    /// packet or error. Doesn't return an Error on expected ICMP errors (such
    /// as host unreachable).
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying IO causes an
    /// unexpected error.
    fn recv(&mut self, timeout: std::time::Duration) -> Result<IcmpResult, std::io::Error>;
}

#[derive(Debug)]
pub enum IcmpType {
    EchoReply(u64),
    TimeExceeded,
    IPv4DestinationUnreachable(Result<IPv4DestinationUnreachable, u8>),
    IPv6DestinationUnreachable(Result<IPv6DestinationUnreachable, u8>),
}

#[repr(u8)]
#[derive(int_enum::IntEnum, Debug)]
pub enum IPv4DestinationUnreachable {
    NetUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTos = 11,
    HostUnreachableForTos = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,
}

#[repr(u8)]
#[derive(int_enum::IntEnum, Debug)]
pub enum IPv6DestinationUnreachable {
    NoRouteToDestination = 0,
    AdministrativelyProhibited = 1,
    BeyondScopeOfSourceAddress = 2,
    AddressUnreachable = 3,
    PortUnreachable = 4,
    PolicyProhibited = 5,
    RouteRejected = 6,
    SourceRoutingFailed = 7,
}

#[derive(Debug)]
pub struct IcmpMessage {
    pub icmp_type: IcmpType,
    pub id: u16,
    pub seq: u16,
    pub timestamp: Option<u64>,
}

#[derive(Debug)]
pub enum IcmpResult {
    IcmpPacket(IcmpPacket),
    RecvError(RecvError),
    Timeout,
    Interrupted,
}

// A received ICMP packet
#[derive(Debug)]
pub struct IcmpPacket {
    // The source address
    pub addr: SocketAddr,
    // The receive ICMP message
    pub message: IcmpMessage,
    // The local time when the packet was received
    pub time: std::time::Instant,
    // The received TTL of the received packet (remaining hops to destination)
    pub recvttl: Option<u32>,
}

// An error that occurred while receiving an ICMP packet
#[derive(Debug)]
pub struct RecvError {
    // The error that occurred
    pub error: std::io::Error,
    // The source address if available (The host that sent the error message)
    pub addr: Option<SocketAddr>,
    // The original ICMP message if included in the error
    pub original_message: Option<IcmpMessage>,
    // Offender IP address if available
    pub offender: Option<SocketAddr>,
    // ICMP type
    pub icmp_type: Option<u8>,
    // ICMP code
    pub icmp_code: Option<u8>,
    // The local time when the error occurred
    pub time: std::time::Instant,
}

pub fn ipv4unreach_to_string(unreach: &Result<IPv4DestinationUnreachable, u8>) -> String {
    match unreach {
        Ok(reason) => reason.to_string(),
        Err(code) => format!("Unknown code: {}", code),
    }
}

pub fn ipv6unreach_to_string(unreach: &Result<IPv6DestinationUnreachable, u8>) -> String {
    match unreach {
        Ok(reason) => reason.to_string(),
        Err(code) => format!("Unknown code: {}", code),
    }
}

impl Display for IPv6DestinationUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IPv6DestinationUnreachable::NoRouteToDestination => {
                write!(f, "No route to destination")
            }
            IPv6DestinationUnreachable::AdministrativelyProhibited => {
                write!(f, "Administratively prohibited")
            }
            IPv6DestinationUnreachable::BeyondScopeOfSourceAddress => {
                write!(f, "Beyond scope of source address")
            }
            IPv6DestinationUnreachable::AddressUnreachable => write!(f, "Address unreachable"),
            IPv6DestinationUnreachable::PortUnreachable => write!(f, "Port unreachable"),
            IPv6DestinationUnreachable::PolicyProhibited => write!(f, "Policy prohibited"),
            IPv6DestinationUnreachable::RouteRejected => write!(f, "Route rejected"),
            IPv6DestinationUnreachable::SourceRoutingFailed => write!(f, "Source routing failed"),
        }
    }
}

impl Display for IPv4DestinationUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IPv4DestinationUnreachable::NetUnreachable => write!(f, "Network unreachable"),
            IPv4DestinationUnreachable::HostUnreachable => write!(f, "Host unreachable"),
            IPv4DestinationUnreachable::ProtocolUnreachable => write!(f, "Protocol unreachable"),
            IPv4DestinationUnreachable::PortUnreachable => write!(f, "Port unreachable"),
            IPv4DestinationUnreachable::FragmentationNeeded => write!(f, "Fragmentation needed"),
            IPv4DestinationUnreachable::SourceRouteFailed => write!(f, "Source route failed"),
            IPv4DestinationUnreachable::DestinationNetworkUnknown => {
                write!(f, "Destination network unknown")
            }
            IPv4DestinationUnreachable::DestinationHostUnknown => {
                write!(f, "Destination host unknown")
            }
            IPv4DestinationUnreachable::SourceHostIsolated => write!(f, "Source host isolated"),
            IPv4DestinationUnreachable::NetworkAdministrativelyProhibited => {
                write!(f, "Network administratively prohibited")
            }
            IPv4DestinationUnreachable::HostAdministrativelyProhibited => {
                write!(f, "Host administratively prohibited")
            }
            IPv4DestinationUnreachable::NetworkUnreachableForTos => {
                write!(f, "Network unreachable for TOS")
            }
            IPv4DestinationUnreachable::HostUnreachableForTos => {
                write!(f, "Host unreachable for TOS")
            }
            IPv4DestinationUnreachable::CommunicationAdministrativelyProhibited => {
                write!(f, "Communication administratively prohibited")
            }
            IPv4DestinationUnreachable::HostPrecedenceViolation => {
                write!(f, "Host precedence violation")
            }
            IPv4DestinationUnreachable::PrecedenceCutoffInEffect => {
                write!(f, "Precedence cutoff in effect")
            }
        }
    }
}

fn parse_icmp_packet(packet: &[u8]) -> Option<IcmpMessage> {
    let icmp_type = packet[0];

    let reply = match icmp_type {
        0 => IcmpType::EchoReply(u64::from_be_bytes(packet[8..16].try_into().unwrap())),
        3 => IcmpType::IPv4DestinationUnreachable(IPv4DestinationUnreachable::try_from(packet[1])),
        _ => {
            println!("Something not echo reply received {}", icmp_type);
            return None;
        }
    };

    let icmp_packet = match reply {
        IcmpType::EchoReply(_) => packet,
        IcmpType::IPv4DestinationUnreachable(_) | IcmpType::TimeExceeded => {
            let payload = &packet[8..];
            let ip_header_length = ((payload[0] & 0x0F) * 4) as usize;
            &payload[ip_header_length..]
        }
        IcmpType::IPv6DestinationUnreachable(_) => {
            let payload = &packet[8..];
            let ip_header_length = 40;
            &payload[ip_header_length..]
        }
    };

    let identifier = u16::from_be_bytes(icmp_packet[4..6].try_into().unwrap());
    let sequence = u16::from_be_bytes(icmp_packet[6..8].try_into().unwrap());
    let timestamp = if icmp_packet.len() >= 16 {
        Some(u64::from_be_bytes(icmp_packet[8..16].try_into().unwrap()))
    } else {
        None
    };

    Some(IcmpMessage {
        icmp_type: reply,
        id: identifier,
        seq: sequence,
        timestamp,
    })
}

fn parse_icmpv6_packet(packet: &[u8]) -> Option<IcmpMessage> {
    let icmp_type = packet[0];

    let reply = match icmp_type {
        1 => IcmpType::IPv6DestinationUnreachable(IPv6DestinationUnreachable::try_from(packet[1])),
        3 => IcmpType::TimeExceeded,
        129 => IcmpType::EchoReply(u64::from_be_bytes(packet[8..16].try_into().unwrap())),
        _ => {
            println!("Something not echo reply received {}", icmp_type);
            return None;
        }
    };

    let icmp_packet = match reply {
        IcmpType::EchoReply(_) => packet,
        IcmpType::IPv4DestinationUnreachable(_) => {
            let payload = &packet[8..];
            let ip_header_length = ((payload[0] & 0x0F) * 4) as usize;
            &payload[ip_header_length..]
        }
        IcmpType::IPv6DestinationUnreachable(_) | IcmpType::TimeExceeded => {
            let payload = &packet[8..];
            let ip_header_length = 40;
            &payload[ip_header_length..]
        }
    };

    let identifier = u16::from_be_bytes(icmp_packet[4..6].try_into().unwrap());
    let sequence = u16::from_be_bytes(icmp_packet[6..8].try_into().unwrap());
    let timestamp = if icmp_packet.len() >= 16 {
        Some(u64::from_be_bytes(icmp_packet[8..16].try_into().unwrap()))
    } else {
        None
    };

    Some(IcmpMessage {
        icmp_type: reply,
        id: identifier,
        seq: sequence,
        timestamp,
    })
}

fn construct_icmp_packet(packet: &mut [u8], icmp_type: u8, code: u8, id: u16, seq: u16, timestamp: u64) {
    packet[0] = icmp_type; // echo request
    packet[1] = code;
    packet[2] = 0; // checksum msb
    packet[3] = 0; // checksum lsb
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

    for (i, item) in packet.iter_mut().enumerate().skip(16) {
        *item = i as u8;
    }

    unsafe {
        // Calculate checksum
        let len = packet.len();
        let word_count = len / 2;

        let mut checksum: u32 = 0;
        let packet_slice = &mut packet[..];
        let packet16: &mut [u16] = std::mem::transmute(packet_slice);
        let data = packet16.as_mut_ptr();
        for pos in 0..word_count {
            let word = *data.add(pos);
            checksum += word as u32;
        }

        if len % 2 == 1 {
            checksum += packet[len - 1] as u32;
        }
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

        let packet16: &mut [u16] = std::mem::transmute(packet);
        let data = packet16.as_mut_ptr();
        *data.offset(1) = (checksum as u16) ^ 0xFFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_ping() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut pinger = PingProtocol::new(target, 64).unwrap();
        let timestamp = 0x4321fedcu64;
        let sequence = 0xde42u16;
        pinger.send(sequence, timestamp).unwrap();
        let packet = pinger.recv(std::time::Duration::from_secs(1)).unwrap();
        // must always be a IcmpPacket
        assert!(matches!(packet, IcmpResult::IcmpPacket(_)));
        // must be an echo reply
        let packet = match packet {
            IcmpResult::IcmpPacket(packet) => packet,
            _ => unreachable!(),
        };
        assert!(matches!(packet.message.icmp_type, IcmpType::EchoReply(_)));
        assert_eq!(
            packet.message.timestamp,
            Some(timestamp),
            "Packet timestamp must be the same as the sent timestamp"
        );
        assert_eq!(
            packet.message.seq, sequence,
            "Packet sequence must be the same as the sent sequence"
        );
        assert_eq!(packet.addr, target, "Packet source address must be the target address");
    }

    #[test]
    fn test_ping_ipv6() {
        let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let mut pinger = PingProtocol::new(target, 64).unwrap();
        let timestamp = 0x4321fedcu64;
        let sequence = 0xde42u16;
        pinger.send(sequence, timestamp).unwrap();
        let packet = pinger.recv(std::time::Duration::from_secs(1)).unwrap();
        // must always be a IcmpPacket
        assert!(matches!(packet, IcmpResult::IcmpPacket(_)));
        // must be an echo reply
        let packet = match packet {
            IcmpResult::IcmpPacket(packet) => packet,
            _ => unreachable!(),
        };
        assert!(
            matches!(packet.message.icmp_type, IcmpType::EchoReply(_)),
            "Packet type must be an echo reply"
        );
        assert_eq!(
            packet.message.timestamp,
            Some(timestamp),
            "Packet timestamp must be the same as the sent timestamp"
        );
        assert_eq!(
            packet.message.seq, sequence,
            "Packet sequence must be the same as the sent sequence"
        );
        assert_eq!(packet.addr, target, "Packet source address must be the target address");
    }

    #[test]
    fn test_ttl_ipv4() -> Result<(), Box<dyn std::error::Error>> {
        let addrs = dns_lookup::lookup_host("google.com")?;
        let addr = addrs.iter().find(|addr| addr.is_ipv4()).unwrap();
        let target = SocketAddr::new(*addr, 0);
        let mut pinger = PingProtocol::new(target, 64)?;
        let timestamp = 0x4321fedcu64;
        let sequence = 0xde42u16;
        pinger.set_ttl(4)?;
        pinger.send(sequence, timestamp)?;
        let packet = pinger.recv(std::time::Duration::from_secs(1))?;
        assert!(matches!(packet, IcmpResult::RecvError(_)));
        let err = match packet {
            IcmpResult::RecvError(err) => err,
            _ => unreachable!(),
        };
        assert_eq!(err.icmp_type, Some(11));
        assert_eq!(err.icmp_code, Some(0));
        assert!(err.offender.is_some());
        assert!(err.offender.unwrap().is_ipv4());
        Ok(())
    }
}
