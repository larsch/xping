mod sockaddr;

#[cfg(feature = "iphelper")]
#[cfg(target_os = "windows")]
pub use windows::IpHelperApi;

#[cfg(target_os = "linux")]
mod linux;

use std::{fmt::Display, net::SocketAddr};

#[cfg(target_os = "linux")]
pub use linux::IcmpSocketApi;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::IcmpSocketApi;

#[cfg(feature = "anyhow")]
type Error = anyhow::Error;

#[cfg(not(feature = "anyhow"))]
type Error = std::io::Error;

/// The ICMP API trait. This trait is implemented by the OS-specific ICMP API
/// implementations.
pub trait IcmpApi {
    fn new() -> Result<Self, Error>
    where
        Self: Sized;

    /// Set the TTL (time-to-live) of ICMP packets sent using the send() method.
    fn set_ttl(&mut self, ttl: u8) -> Result<(), Error>;

    /// Send an ICMP packet with the given sequence number and timestamp. The
    /// timestamp is inserted into the ICMP payload and can be used to calculate
    /// the round-trip time.
    ///
    /// # Arguments
    /// * `target` - The target IP address
    /// * `length` - The length of the ICMP payload
    /// * `seq` - The sequence number of the packet
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying IO causes an
    /// unexpected error.
    ///
    /// # Returns
    ///
    /// The function returns the time when the packet was sent.
    fn send(&mut self, target: std::net::IpAddr, length: usize, seq: u16) -> Result<std::time::SystemTime, Error>;

    /// Wait for the next ICMP packet, error, or timeout. Returns the received
    /// packet or error. Doesn't return an Error on expected ICMP errors (such
    /// as host unreachable). This function will block until a packet is
    /// received, an error occurs, or the timeout is reached.
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying IO causes an
    /// unexpected error.
    fn recv(&mut self, timeout: std::time::Duration) -> Result<RecvResult, Error>;
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
    pub timestamp: Option<std::time::SystemTime>,
}

#[derive(Debug)]
pub enum RecvResult {
    /// An ICMP packet was received
    EchoReply(EchoReply),
    /// An error occurred while receiving an ICMP packet
    RecvError(RecvError),
    /// Timeout occurred while waiting for a packet
    RecvTimeout,
    /// The receive operation was interrupted
    Interrupted,
}

// A received ICMP packet
#[derive(Debug)]
pub struct EchoReply {
    // The source address
    pub addr: SocketAddr,
    // The receive ICMP message
    pub message: IcmpMessage,
    // The local time when the packet was received
    pub timestamp: std::time::SystemTime,
    // The received TTL of the received packet (remaining hops to destination)
    pub recvttl: Option<u32>,
    /// OS timestamp of the packet
    pub socket_timestamp: Option<std::time::SystemTime>,
}

// An error that occurred while receiving an ICMP packet
#[derive(Debug)]
pub struct RecvError {
    // The OS error that occurred (if any)
    pub error: Option<Error>,
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
    pub time: std::time::SystemTime,
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

pub fn timestamp_from_payload(payload: &[u8]) -> Option<std::time::SystemTime> {
    if payload.len() < 16 {
        return None;
    }
    let seconds = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let nanoseconds = u64::from_le_bytes(payload[8..16].try_into().unwrap());
    Some(std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanoseconds as u32))
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
    let timestamp = timestamp_from_payload(&icmp_packet[8..]);

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
    let timestamp = if icmp_packet.len() >= 24 {
        let seconds = u64::from_le_bytes(icmp_packet[8..16].try_into().unwrap());
        let nanoseconds = u64::from_le_bytes(icmp_packet[16..24].try_into().unwrap());
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(seconds, nanoseconds as u32))
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

fn construct_icmp_payload(payload: &mut [u8], timestamp: std::time::SystemTime) {
    let timestamp = timestamp.duration_since(std::time::UNIX_EPOCH).unwrap();
    // Copy the timestamp into the payload, Wireshark format
    payload[0..8].copy_from_slice(&timestamp.as_secs().to_le_bytes());
    payload[8..16].copy_from_slice(&(timestamp.subsec_nanos() as u64).to_le_bytes());
    // Fill the rest of the payload with incrementing numbers
    for (i, item) in payload.iter_mut().enumerate().skip(16) {
        *item = i as u8;
    }
}

fn construct_icmp_packet(packet: &mut [u8], icmp_type: u8, code: u8, id: u16, seq: u16, timestamp: std::time::SystemTime) {
    packet[0] = icmp_type; // echo request
    packet[1] = code;
    packet[2] = 0; // checksum msb
    packet[3] = 0; // checksum lsb
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());

    construct_icmp_payload(&mut packet[8..], timestamp);

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
    use lazy_static::lazy_static;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    lazy_static! {
        /// A mutex to ensure that tests don't run concurrently
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn test_ping_icmpsocket() {
        test_ping::<super::IcmpSocketApi>();
    }

    #[test]
    #[cfg(windows)]
    #[cfg(feature = "iphelper")]
    fn test_ping_iphelper() {
        test_ping::<super::IpHelperApi>();
    }

    fn test_ping<T: IcmpApi>() {
        let _lock = TEST_MUTEX.lock().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut pinger = T::new().unwrap();
        let sequence = 0xde42u16;
        let tx_timestamp = pinger.send(target, 64, sequence).unwrap();
        let packet = pinger.recv(std::time::Duration::from_secs(1)).unwrap();
        // must always be a IcmpPacket
        assert!(matches!(packet, RecvResult::EchoReply(_)));
        // must be an echo reply
        let packet = match packet {
            RecvResult::EchoReply(packet) => packet,
            _ => unreachable!(),
        };
        assert!(matches!(packet.message.icmp_type, IcmpType::EchoReply(_)));
        assert_eq!(
            packet.message.timestamp,
            Some(tx_timestamp),
            "Packet timestamp must be the same as the sent timestamp"
        );
        assert_eq!(
            packet.message.seq, sequence,
            "Packet sequence must be the same as the sent sequence"
        );
        assert_eq!(packet.addr.ip(), target, "Packet source address must be the target address");
        if let Some(timestamp) = packet.socket_timestamp {
            let rtt = timestamp.duration_since(tx_timestamp).unwrap();
            println!("Round trip time: {:?}", rtt);
            assert!(timestamp >= tx_timestamp);
        }
    }

    #[test]
    fn test_ping_ipv6_icmpsocket() {
        test_ping_ipv6::<super::IcmpSocketApi>();
    }

    #[test]
    #[cfg(windows)]
    #[cfg(feature = "iphelper")]
    fn test_ping_ipv6_iphelper() {
        test_ping_ipv6::<super::IpHelperApi>();
    }

    fn test_ping_ipv6<T: IcmpApi>() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let target = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut pinger = T::new().unwrap();
        let sequence = 0xde42u16;
        let timestamp = pinger.send(target, 64, sequence).unwrap();
        let packet = pinger.recv(std::time::Duration::from_secs(1)).unwrap();
        // must always be a IcmpPacket
        assert!(matches!(packet, RecvResult::EchoReply(_)));
        // must be an echo reply
        let packet = match packet {
            RecvResult::EchoReply(packet) => packet,
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
        assert_eq!(packet.addr.ip(), target, "Packet source address must be the target address");
    }

    #[test]
    #[cfg(not(feature = "skip-network-tests"))]
    fn ping_google_ipv4_recvttl_icmpsocket() -> Result<(), Box<dyn std::error::Error>> {
        ping_google_ipv4_recvttl::<super::IcmpSocketApi>()
    }

    #[test]
    #[cfg(windows)]
    #[cfg(feature = "iphelper")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn ping_google_ipv4_recvttl_iphelper() -> Result<(), Box<dyn std::error::Error>> {
        ping_google_ipv4_recvttl::<super::IpHelperApi>()
    }

    #[cfg(not(feature = "skip-network-tests"))]
    fn ping_google_ipv4_recvttl<T: IcmpApi>() -> Result<(), Box<dyn std::error::Error>> {
        let _lock = TEST_MUTEX.lock().unwrap();
        let addrs = dns_lookup::lookup_host("google.com")?;
        let addr = addrs.iter().find(|addr| addr.is_ipv4()).unwrap();
        let mut pinger = T::new()?;
        let sequence = 0xde42u16;
        let _timestamp = pinger.send(*addr, 64, sequence)?;
        let packet = pinger.recv(std::time::Duration::from_secs(1))?;
        assert!(matches!(packet, RecvResult::EchoReply(_)));
        let packet = match packet {
            RecvResult::EchoReply(packet) => packet,
            _ => unreachable!(),
        };
        assert!(packet.recvttl.is_some());
        assert!(packet.recvttl.unwrap() <= 255);
        Ok(())
    }

    #[test]
    #[cfg(not(feature = "skip-network-tests"))]
    fn ping_google_ipv6_recvttl_icmpsocket() {
        ping_google_ipv6_recvttl::<super::IcmpSocketApi>().unwrap();
    }

    #[cfg(not(feature = "skip-network-tests"))]
    fn ping_google_ipv6_recvttl<T: IcmpApi>() -> Result<(), Box<dyn std::error::Error>> {
        let _lock = TEST_MUTEX.lock().unwrap();
        let addrs = dns_lookup::lookup_host("google.com")?;
        let addr = addrs.iter().find(|addr| addr.is_ipv6()).unwrap();
        let target = *addr;
        let mut pinger = T::new()?;
        let sequence = 0xde42u16;
        let _timestamp = pinger.send(target, 64, sequence)?;
        let packet = pinger.recv(std::time::Duration::from_secs(1))?;
        assert!(matches!(packet, RecvResult::EchoReply(_)));
        let packet = match packet {
            RecvResult::EchoReply(packet) => packet,
            _ => unreachable!(),
        };
        assert!(packet.recvttl.is_some());
        assert!(packet.recvttl.unwrap() <= 255);
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv4_icmpsocket() -> Result<(), Box<dyn std::error::Error>> {
        test_ttl_ipv4::<super::IcmpSocketApi>()
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[cfg(feature = "iphelper")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv4_iphelper() -> Result<(), Box<dyn std::error::Error>> {
        test_ttl_ipv4::<super::IpHelperApi>()
    }

    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv4<T: IcmpApi>() -> Result<(), Box<dyn std::error::Error>> {
        let _lock = TEST_MUTEX.lock().unwrap();
        let addrs = dns_lookup::lookup_host("google.com")?;
        let addr = addrs.iter().find(|addr| addr.is_ipv4()).unwrap();
        let mut pinger = T::new()?;
        let sequence = 0xde42u16;
        pinger.set_ttl(4)?;
        let _timestamp = pinger.send(*addr, 64, sequence)?;
        let packet = pinger.recv(std::time::Duration::from_secs(1))?;
        assert!(matches!(packet, RecvResult::RecvError(_)));
        let err = match packet {
            RecvResult::RecvError(err) => err,
            _ => unreachable!(),
        };
        assert_eq!(err.icmp_type, Some(11));
        assert_eq!(err.icmp_code, Some(0));
        assert!(err.offender.is_some());
        assert!(err.offender.unwrap().is_ipv4());
        Ok(())
    }

    #[test]
    #[cfg(target_os = "windows")]
    #[cfg(feature = "iphelper")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv6_iphelper() -> Result<(), Box<dyn std::error::Error>> {
        test_ttl_ipv6::<super::IpHelperApi>()
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv6_icmpsocket() -> Result<(), Box<dyn std::error::Error>> {
        test_ttl_ipv6::<super::IcmpSocketApi>()
    }

    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ttl_ipv6<T: IcmpApi>() -> Result<(), Box<dyn std::error::Error>> {
        let _lock = TEST_MUTEX.lock().unwrap();
        let addrs = dns_lookup::lookup_host("google.com")?;
        let addr = addrs.iter().find(|addr| addr.is_ipv6()).unwrap();
        let mut pinger = T::new()?;
        let _timestamp = 0x4321fedcu64;
        let sequence = 0xde42u16;
        pinger.set_ttl(4)?;
        let _timestamp = pinger.send(*addr, 64, sequence)?;
        let packet = pinger.recv(std::time::Duration::from_secs(1))?;
        assert!(matches!(packet, RecvResult::RecvError(_)));
        let err = match packet {
            RecvResult::RecvError(err) => err,
            _ => unreachable!(),
        };
        #[cfg(target_os = "windows")]
        assert_eq!(err.icmp_type, Some(11));
        #[cfg(not(target_os = "windows"))]
        assert_eq!(err.icmp_type, Some(3));
        assert_eq!(err.icmp_code, Some(0));
        assert!(err.offender.is_some());
        assert!(err.offender.unwrap().is_ipv6());
        Ok(())
    }

    #[test]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ping_multiple_icmpsocket() -> Result<(), Box<dyn std::error::Error>> {
        test_ping_multiple::<super::IcmpSocketApi>()
    }

    #[test]
    #[cfg(windows)]
    #[cfg(feature = "iphelper")]
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ping_multiple_iphelper() -> Result<(), Box<dyn std::error::Error>> {
        test_ping_multiple::<super::IpHelperApi>()
    }

    /// Test sending multiple ICMP packets to multiple addresses
    #[cfg(not(feature = "skip-network-tests"))]
    fn test_ping_multiple<T: IcmpApi>() -> Result<(), Box<dyn std::error::Error>> {
        let _lock = TEST_MUTEX.lock().unwrap();
        let addrs1 = dns_lookup::lookup_host("google.com")?;
        let addrs2 = dns_lookup::lookup_host("gmail.com")?;
        let addrs = addrs1.iter().chain(addrs2.iter());
        let ipv4addrs: Vec<IpAddr> = addrs.filter(|addr| addr.is_ipv4()).cloned().collect();
        assert!(ipv4addrs.len() > 1);
        let mut pinger = T::new()?;
        let sequence = 0xde42u16;
        for addr in &ipv4addrs {
            pinger.send(*addr, 64, sequence)?;
        }
        let mut remaining: std::collections::HashSet<IpAddr> = ipv4addrs.iter().cloned().collect();
        while !remaining.is_empty() {
            let packet = pinger.recv(std::time::Duration::from_secs(1))?;
            let packet = match packet {
                RecvResult::EchoReply(packet) => packet,
                _ => unreachable!(),
            };
            assert!(remaining.remove(&packet.addr.ip()));
        }
        Ok(())
    }
}
