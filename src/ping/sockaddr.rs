use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(target_os = "linux")]
use crate::ping::linux::types::*;

#[cfg(target_os = "windows")]
use crate::ping::windows::types::*;

pub union SockAddr {
    sa: sockaddr,
    sin: sockaddr_in,
    pub sin6: sockaddr_in6,
}

impl Default for SockAddr {
    fn default() -> Self {
        SockAddr {
            sa: unsafe { std::mem::zeroed() },
        }
    }
}

impl Clone for SockAddr {
    fn clone(&self) -> Self {
        SockAddr { sa: unsafe { self.sa } }
    }
}

impl SockAddr {
    pub fn sa_family(&self) -> AddressFamily {
        unsafe { self.sa.sa_family as AddressFamily }
    }
}

impl AsRef<sockaddr> for SockAddr {
    fn as_ref(&self) -> &sockaddr {
        unsafe { &self.sa }
    }
}

impl AsMut<sockaddr> for SockAddr {
    fn as_mut(&mut self) -> &mut sockaddr {
        unsafe { &mut self.sa }
    }
}

pub trait TryFromOsSockAddr {
    fn from_sockaddr(raw: *const sockaddr) -> Result<Self, String>
    where
        Self: Sized;
}

impl TryFromOsSockAddr for SocketAddr {
    fn from_sockaddr(raw: *const sockaddr) -> Result<SocketAddr, String> {
        let sockaddr_sa = unsafe { &*(raw as *const sockaddr) };
        println!("sockaddr_sa.sa_family: {:?}", sockaddr_sa.sa_family);
        match sockaddr_sa.sa_family as AddressFamily {
            AF_INET => {
                let sockaddr_in = unsafe { &*(raw as *const sockaddr_in) };
                let port = u16::from_be(sockaddr_in.sin_port);
                Ok(SocketAddr::V4(SocketAddrV4::new(sockaddr_in.sin_addr.as_ipv4addr(), port)))
            }
            AF_INET6 => {
                let sockaddr_in6 = unsafe { &*(raw as *const sockaddr_in6) };
                let port = u16::from_be(sockaddr_in6.sin6_port);
                Ok(SocketAddr::V6(SocketAddrV6::new(sockaddr_in6.sin6_addr.as_ipv6addr(), port, 0, 0)))
            }
            _ => panic!("Unhandled address family"),
        }
    }
}

impl TryFrom<SockAddr> for SocketAddr {
    type Error = String;

    fn try_from(value: SockAddr) -> Result<SocketAddr, Self::Error> {
        match value.sa_family() {
            AF_INET => {
                let sockaddr_in: &sockaddr_in = unsafe { &value.sin };
                let port = u16::from_be(sockaddr_in.sin_port);
                Ok(SocketAddr::V4(SocketAddrV4::new(sockaddr_in.sin_addr.as_ipv4addr(), port)))
            }
            AF_INET6 => {
                let sockaddr_in6 = unsafe { &value.sin6 };
                let port = u16::from_be(sockaddr_in6.sin6_port);
                Ok(SocketAddr::V6(SocketAddrV6::new(sockaddr_in6.sin6_addr.as_ipv6addr(), port, 0, 0)))
            }
            _ => Err("Unhandled address family".to_owned()),
        }
    }
}

impl From<SocketAddr> for SockAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4addr) => {
                let ip = v4addr.ip().octets();
                let port = v4addr.port().to_be();
                let sockaddr_in = unsafe {
                    sockaddr_in {
                        sin_family: AF_INET,
                        sin_port: port,
                        sin_addr: in_addr::from_octets(&ip),
                        ..std::mem::zeroed()
                    }
                };
                SockAddr { sin: sockaddr_in }
            }
            SocketAddr::V6(v6addr) => {
                let ip = v6addr.ip().octets();
                let port = v6addr.port().to_be();
                let sockaddr_in6 = unsafe {
                    sockaddr_in6 {
                        sin6_family: AF_INET6,
                        sin6_port: port,
                        sin6_addr: in6_addr::from_octets(&ip),
                        ..std::mem::zeroed()
                    }
                };
                SockAddr { sin6: sockaddr_in6 }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_sockaddr_from() {
        // Test IPv4 address
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 8443;
        let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa.sa_family, AF_INET);
            assert_eq!(sockaddr.sin.sin_port, port.to_be());
            assert_eq!(sockaddr.sin.sin_addr.as_ipv4addr(), ip);
        }

        // Test IPv6 address
        let ip = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let port = 8443;
        let socket_addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa_family(), AF_INET6);
            assert_eq!(sockaddr.sin6.sin6_port, port.to_be());
            assert_eq!(sockaddr.sin6.sin6_addr.as_ipv6addr(), ip);
        }
    }

    #[test]
    fn test_sockaddr_tryinto() {
        // Test IPv4 address
        let sockaddr = SockAddr {
            sin: sockaddr_in {
                sin_family: AF_INET,
                sin_port: 8443u16.to_be(),
                sin_addr: in_addr::from_octets(&[127, 0, 0, 1]),
                ..unsafe { std::mem::zeroed() }
            },
        };

        let socket_addr: SocketAddr = sockaddr.try_into().unwrap();
        assert_eq!(socket_addr, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8443)));

        // Test IPv6 address
        let sockaddr = SockAddr {
            sin6: sockaddr_in6 {
                sin6_family: AF_INET6,
                sin6_port: 8080u16.to_be(),
                sin6_addr: in6_addr::from_octets(&[0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]),
                ..unsafe { std::mem::zeroed() }
            },
        };
        let socket_addr: SocketAddr = sockaddr.try_into().unwrap();
        assert_eq!(
            socket_addr,
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8), 8080, 0, 0))
        );
    }
}
