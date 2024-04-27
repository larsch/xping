use std::{env, mem, net};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socketaddr_to_sockaddr() {
        // Test IPv4 address
        let ip = net::Ipv4Addr::new(127, 0, 0, 1);
        let port = 8443;
        let socket_addr = net::SocketAddr::V4(net::SocketAddrV4::new(ip, port));
        let sockaddr = socketaddr_to_sockaddr(socket_addr).unwrap();
        unsafe {
            assert_eq!(sockaddr.sa.sa_family as i32, libc::AF_INET);
            assert_eq!(sockaddr.sin.sin_port, port.to_be());
            assert_eq!(sockaddr.sin.sin_addr.s_addr, u32::from(ip).to_be());
        }

        // Test IPv6 address
        let ip = net::Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
        let port = 8443;
        let socket_addr = net::SocketAddr::V6(net::SocketAddrV6::new(ip, port, 0, 0));
        let sockaddr = socketaddr_to_sockaddr(socket_addr).unwrap();
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
                    s_addr: u32::from(net::Ipv4Addr::new(127, 0, 0, 1)).to_be(),
                },
                ..unsafe { mem::zeroed() }
            },
        };

        let socket_addr = sockaddr_to_socketaddr(&sockaddr).unwrap();
        assert_eq!(
            socket_addr,
            net::SocketAddr::V4(net::SocketAddrV4::new(
                net::Ipv4Addr::new(127, 0, 0, 1),
                8443
            ))
        );

        // Test IPv6 address
        let sockaddr = SockAddr {
            sin6: libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: 8080u16.to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8],
                },
                ..unsafe { mem::zeroed() }
            },
        };
        let socket_addr = sockaddr_to_socketaddr(&sockaddr).unwrap();
        assert_eq!(
            socket_addr,
            net::SocketAddr::V6(net::SocketAddrV6::new(
                net::Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8),
                8080,
                0,
                0
            ))
        );
    }
}

fn sockaddr_to_socketaddr(addr: &SockAddr) -> Result<net::SocketAddr, String> {
    match unsafe { addr.sa.sa_family as i32 } {
        libc::AF_INET => {
            let sockaddr_in: &libc::sockaddr_in = unsafe { &addr.sin };
            let s_addr = u32::from_be(sockaddr_in.sin_addr.s_addr);
            let ip = net::Ipv4Addr::new(
                ((s_addr >> 24) & 0xFF) as u8,
                ((s_addr >> 16) & 0xFF) as u8,
                ((s_addr >> 8) & 0xFF) as u8,
                (s_addr & 0xFF) as u8,
            );
            let port = u16::from_be(sockaddr_in.sin_port);
            Ok(net::SocketAddr::V4(net::SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sockaddr_in6 = unsafe { &addr.sin6 };
            let a: [u16; 8] = unsafe { mem::transmute(sockaddr_in6.sin6_addr.s6_addr) };
            let a: [u16; 8] = a
                .iter()
                .map(|&x| u16::from_be(x))
                .collect::<Vec<u16>>()
                .try_into()
                .unwrap();
            let ip = net::Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
            let port = u16::from_be(sockaddr_in6.sin6_port);
            Ok(net::SocketAddr::V6(net::SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => Err("Unhandled address family".to_owned()),
    }
}

union SockAddr {
    sa: libc::sockaddr,
    sin: libc::sockaddr_in,
    sin6: libc::sockaddr_in6,
}

fn socketaddr_to_sockaddr(addr: net::SocketAddr) -> Result<SockAddr, String> {
    match addr {
        net::SocketAddr::V4(v4addr) => {
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
            Ok(SockAddr { sin: sockaddr_in })
        }
        net::SocketAddr::V6(v6addr) => {
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
            Ok(SockAddr { sin6: sockaddr_in6 })
        }
    }
}
struct PingProtocol {
    socket: i32,
    target: SockAddr,
    target_sa: net::SocketAddr,
}

impl PingProtocol {
    fn new(target_sa: net::SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let target = socketaddr_to_sockaddr(target_sa)?;
        let target_family = match target_sa {
            net::SocketAddr::V4(_) => libc::AF_INET,
            net::SocketAddr::V6(_) => libc::AF_INET6,
        };
        let ipproto = match target_sa {
            net::SocketAddr::V4(_) => libc::IPPROTO_ICMP,
            net::SocketAddr::V6(_) => libc::IPPROTO_ICMPV6,
        };
        let socket = unsafe { libc::socket(target_family, libc::SOCK_DGRAM, ipproto) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(Self {
            socket,
            target,
            target_sa,
        })
    }

    fn send(&self) -> Result<(), std::io::Error> {
        let mut icmp_packet: [u8; 192] = [0; 192];
        let code = match self.target_sa {
            net::SocketAddr::V4(_) => 0x08,
            net::SocketAddr::V6(_) => 0x80,
        };
        let icmp_prefix: [u8; 16] = [code, 0, 0, 0, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7];
        icmp_packet[0..16].copy_from_slice(&icmp_prefix);

        let buf = &icmp_packet as *const u8 as *const libc::c_void;
        let result = unsafe {
            libc::sendto(
                self.socket,
                buf,
                icmp_packet.len(),
                0,
                &self.target.sa,
                std::mem::size_of::<SockAddr>() as u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self) -> Result<Option<net::SocketAddr>, Box<dyn std::error::Error>> {
        let mut buf = [0u8; 65536];
        let buf_ptr = &mut buf as *mut u8 as *mut libc::c_void;
        let flags = 0;
        let mut addr: SockAddr = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<SockAddr>() as u32;
        let addrlen_ptr = &mut addr_len as *mut u32;
        let recvfrom_result = unsafe {
            libc::recvfrom(
                self.socket,
                buf_ptr,
                buf.len(),
                flags,
                &mut addr.sa,
                addrlen_ptr,
            )
        };
        if recvfrom_result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        let addr = sockaddr_to_socketaddr(&addr)?;
        Ok(Some(addr))
    }
}

fn main() {
    let target = env::args().nth(1).unwrap();
    let target = dns_lookup::lookup_host(&target).unwrap();
    let target = target.first().unwrap();
    let target_sa = match target {
        net::IpAddr::V4(v4addr) => net::SocketAddr::V4(net::SocketAddrV4::new(*v4addr, 58)),
        net::IpAddr::V6(v6addr) => net::SocketAddr::V6(net::SocketAddrV6::new(*v6addr, 58, 0, 0)),
    };

    let ping_protocol = PingProtocol::new(target_sa).unwrap();

    ping_protocol.send().unwrap();

    let response = ping_protocol.recv().unwrap();
    println!("response from {:?}", response);

    // Rest of the code...
}
