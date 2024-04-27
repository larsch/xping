use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub union SockAddr {
    sa: libc::sockaddr,
    sin: libc::sockaddr_in,
    sin6: libc::sockaddr_in6,
}

impl AsRef<libc::sockaddr> for SockAddr {
    fn as_ref(&self) -> &libc::sockaddr {
        unsafe { &self.sa }
    }
}

impl AsMut<libc::sockaddr> for SockAddr {
    fn as_mut(&mut self) -> &mut libc::sockaddr {
        unsafe { &mut self.sa }
    }
}

impl TryInto<SocketAddr> for SockAddr {
    type Error = String;

    fn try_into(self) -> Result<SocketAddr, Self::Error> {
        match unsafe { self.sa.sa_family as i32 } {
            libc::AF_INET => {
                let sockaddr_in: &libc::sockaddr_in = unsafe { &self.sin };
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
            libc::AF_INET6 => {
                let sockaddr_in6 = unsafe { &self.sin6 };
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
                    libc::sockaddr_in {
                        sin_family: libc::AF_INET as u16,
                        sin_port: port,
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_be_bytes(ip).to_be(),
                        },
                        ..std::mem::zeroed()
                    }
                };
                SockAddr { sin: sockaddr_in }
            }
            SocketAddr::V6(v6addr) => {
                let ip = v6addr.ip().octets();
                let port = v6addr.port().to_be();
                let sockaddr_in6 = unsafe {
                    libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as u16,
                        sin6_port: port,
                        sin6_addr: libc::in6_addr { s6_addr: ip },
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

    #[test]
    fn test_socketaddr_to_sockaddr() {
        // Test IPv4 address
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let port = 8443;
        let socket_addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa.sa_family as i32, libc::AF_INET);
            assert_eq!(sockaddr.sin.sin_port, port.to_be());
            assert_eq!(sockaddr.sin.sin_addr.s_addr, u32::from(ip).to_be());
        }

        // Test IPv6 address
        let ip = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let port = 8443;
        let socket_addr = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0));
        let sockaddr = SockAddr::from(socket_addr);
        unsafe {
            assert_eq!(sockaddr.sa.sa_family as i32, libc::AF_INET6);
            assert_eq!(sockaddr.sin6.sin6_port, port.to_be());
            assert_eq!(sockaddr.sin6.sin6_addr.s6_addr, ip.octets());
        }
    }

    #[test]
    fn test_sockaddr_to_socketaddr() {
        // Test IPv4 address
        let sockaddr = SockAddr {
            sin: libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 8443u16.to_be(),
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
            sin6: libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: 8080u16.to_be(),
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
