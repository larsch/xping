use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
        SockAddr {
            sa: unsafe { self.sa },
        }
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

impl TryFrom<SockAddr> for SocketAddr {
    type Error = String;

    fn try_from(value: SockAddr) -> Result<SocketAddr, Self::Error> {
        match value.sa_family() {
            AF_INET => {
                let sockaddr_in: &sockaddr_in = unsafe { &value.sin };

                #[cfg(target_os = "windows")]
                let s_addr = u32::from_be(unsafe { sockaddr_in.sin_addr.S_un.S_addr });
                #[cfg(target_os = "linux")]
                let s_addr = u32::from_be(sockaddr_in.sin_addr.s_addr);

                let ip = Ipv4Addr::new(
                    ((s_addr >> 24) & 0xFF) as u8,
                    ((s_addr >> 16) & 0xFF) as u8,
                    ((s_addr >> 8) & 0xFF) as u8,
                    (s_addr & 0xFF) as u8,
                );
                let port = u16::from_be(sockaddr_in.sin_port);
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            AF_INET6 => {
                let sockaddr_in6 = unsafe { &value.sin6 };
                #[cfg(target_os = "windows")]
                let a: [u16; 8] = unsafe { sockaddr_in6.sin6_addr.u.Word };
                #[cfg(target_os = "linux")]
                let a: [u16; 8] = unsafe { std::mem::transmute(sockaddr_in6.sin6_addr.s6_addr) };
                let a: [u16; 8] = a
                    .iter()
                    .map(|&x| u16::from_be(x))
                    .collect::<Vec<u16>>()
                    .try_into()
                    .unwrap();
                let ip = Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
                let port = u16::from_be(sockaddr_in6.sin6_port);
                Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
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
    #[cfg(target_os = "windows")]
    use windows::Win32::Networking::WinSock;

    #[test]
    fn test_socketaddr_to_sockaddr() {
        // Test IPv4 address
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 8443;
        let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa.sa_family, AF_INET);
            assert_eq!(sockaddr.sin.sin_port, port.to_be());
            #[cfg(target_os = "windows")]
            assert_eq!(sockaddr.sin.sin_addr.S_un.S_addr, u32::from(ip).to_be());
            #[cfg(target_os = "linux")]
            assert_eq!(sockaddr.sin.sin_addr.s_addr, u32::from(ip).to_be());
        }

        // Test IPv6 address
        let ip = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let port = 8443;
        let socket_addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa_family(), AF_INET6);
            assert_eq!(sockaddr.sin6.sin6_port, port.to_be());
            #[cfg(target_os = "windows")]
            assert_eq!(
                sockaddr.sin6.sin6_addr.u.Byte,
                [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]
            );
            #[cfg(target_os = "linux")]
            assert_eq!(sockaddr.sin6.sin6_addr.s6_addr, ip.octets());
        }
    }

    #[test]
    fn test_sockaddr_to_socketaddr() {
        // Test IPv4 address
        let sockaddr = SockAddr {
            sin: sockaddr_in {
                sin_family: AF_INET,
                sin_port: 8443u16.to_be(),
                #[cfg(target_os = "windows")]
                sin_addr: WinSock::IN_ADDR {
                    S_un: WinSock::IN_ADDR_0 {
                        S_un_b: WinSock::IN_ADDR_0_0 {
                            s_b1: 127,
                            s_b2: 0,
                            s_b3: 0,
                            s_b4: 1,
                        },
                    },
                },
                #[cfg(target_os = "linux")]
                sin_addr: libc::in_addr {
                    s_addr: u32::from(Ipv4Addr::new(127, 0, 0, 1)).to_be(),
                },
                ..unsafe { std::mem::zeroed() }
            },
        };

        let socket_addr: SocketAddr = sockaddr.try_into().unwrap();
        assert_eq!(
            socket_addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8443))
        );

        // Test IPv6 address
        let sockaddr = SockAddr {
            sin6: sockaddr_in6 {
                sin6_family: AF_INET6,
                sin6_port: 8080u16.to_be(),
                #[cfg(target_os = "windows")]
                sin6_addr: WinSock::IN6_ADDR {
                    u: WinSock::IN6_ADDR_0 {
                        Byte: [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8],
                    },
                },
                #[cfg(target_os = "linux")]
                sin6_addr: libc::in6_addr {
                    s6_addr: [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8],
                },
                ..unsafe { std::mem::zeroed() }
            },
        };
        let socket_addr: SocketAddr = sockaddr.try_into().unwrap();
        assert_eq!(
            socket_addr,
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
                8080,
                0,
                0
            ))
        );
    }
}
