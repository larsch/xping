mod icmp_socket;

use std::net::SocketAddr;

use super::sockaddr::TryFromOsSockAddr;

pub use icmp_socket::IcmpSocketApi;

pub mod types {
    pub use libc::sockaddr;
    pub use libc::sockaddr_in;
    pub use libc::sockaddr_in6;
    pub const AF_INET: u16 = libc::AF_INET as u16;
    pub const AF_INET6: u16 = libc::AF_INET6 as u16;
    pub type AddressFamily = u16;
    pub use super::{AsIpv4Addr, AsIpv6Addr, FromOctets};
    pub use libc::in6_addr;
    pub use libc::in_addr;
}

pub trait FromOctets {
    fn from_octets(octets: &[u8]) -> Self;
}

impl FromOctets for libc::in_addr {
    fn from_octets(octets: &[u8]) -> Self {
        let mut addr = libc::in_addr { s_addr: 0 };
        addr.s_addr = u32::from_be_bytes(octets.try_into().unwrap()).to_be();
        addr
    }
}

impl FromOctets for libc::in6_addr {
    fn from_octets(octets: &[u8]) -> Self {
        let mut addr = libc::in6_addr { s6_addr: [0; 16] };
        addr.s6_addr.copy_from_slice(octets);
        addr
    }
}

pub trait AsIpv4Addr {
    fn as_ipv4addr(&self) -> std::net::Ipv4Addr;
}

impl AsIpv4Addr for libc::in_addr {
    fn as_ipv4addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.s_addr.to_be())
    }
}

pub trait AsIpv6Addr {
    fn as_ipv6addr(&self) -> std::net::Ipv6Addr;
}

impl AsIpv6Addr for libc::in6_addr {
    fn as_ipv6addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(self.s6_addr)
    }
}

struct IcmpExtendedSocketErr {
    errno: i32,
    offender: Option<SocketAddr>,
    icmp_type: u8,
    icmp_code: u8,
}

impl From<&libc::sock_extended_err> for IcmpExtendedSocketErr {
    fn from(err: &libc::sock_extended_err) -> Self {
        let offender = match err.ee_errno as i32 {
            libc::EHOSTUNREACH | libc::ENETUNREACH => {
                let addr = unsafe { libc::SO_EE_OFFENDER(err) };
                if addr.is_null() {
                    None
                } else {
                    match SocketAddr::from_sockaddr(addr) {
                        Ok(addr) => Some(addr),
                        Err(_) => None,
                    }
                }
            }
            _ => None,
        };
        Self {
            errno: err.ee_errno as i32,
            offender,
            icmp_type: err.ee_type,
            icmp_code: err.ee_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FromOctets;
    #[test]
    fn test_from_octets() {
        let octets = [192, 168, 1, 1];
        let addr = libc::in_addr::from_octets(&octets);
        assert_eq!(addr.s_addr, 0xc0a80101_u32.to_be());
    }

    #[test]
    fn test_from_octets_v6() {
        let octets = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x02, 0x20, 0x6c, 0x34, 0x00, 0x00, 0x00, 0x01,
        ];
        let addr = libc::in6_addr::from_octets(&octets);
        assert_eq!(addr.s6_addr, octets);
    }
}
