use std::net::SocketAddr;

use super::sockaddr::SockAddr;

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

pub struct PingProtocol {
    socket: i32,
    target: SockAddr,
    target_sa: SocketAddr,
    packet: Vec<u8>,
    length: usize,
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

impl super::Pinger for PingProtocol {
    fn new(target: SocketAddr, length: usize) -> Result<Self, std::io::Error> {
        let sockaddr = SockAddr::from(target);
        let target_family = match target {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        };
        let ipproto = match target {
            SocketAddr::V4(_) => libc::IPPROTO_ICMP,
            SocketAddr::V6(_) => libc::IPPROTO_ICMPV6,
        };
        let socket = unsafe { libc::socket(target_family, libc::SOCK_DGRAM, ipproto) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(Self {
            socket,
            target: sockaddr,
            target_sa: target,
            packet: vec![0u8; length + 8],
            length,
        })
    }

    fn send(&mut self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        self.packet.resize(self.length + 8, 0u8);
        let icmp_type = match self.target_sa {
            SocketAddr::V4(_) => 0x08,
            SocketAddr::V6(_) => 0x80,
        };
        let code = 0;
        let id = sequence;
        super::construct_icmp_packet(&mut self.packet, icmp_type, code, id, sequence, timestamp);
        // let icmp_prefix: [u8; 16] = [icmp_type, 0, 0, 0, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7];
        // icmp_packet[0..16].copy_from_slice(&icmp_prefix);
        // icmp_packet[4..6].copy_from_slice(&sequence.to_be_bytes());
        // icmp_packet[6..8].copy_from_slice(&sequence.to_be_bytes());
        // icmp_packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

        let buf = self.packet.as_mut_ptr();
        let result = unsafe {
            libc::sendto(
                self.socket,
                buf as *const libc::c_void,
                self.packet.len(),
                0,
                self.target.as_ref(),
                std::mem::size_of::<SockAddr>() as u32,
            )
        };
        if result < 0 {
            let last_error = std::io::Error::last_os_error();
            match last_error.kind() {
                std::io::ErrorKind::WouldBlock => Ok(()),
                _ => Err(last_error),
            }
        } else {
            Ok(())
        }
    }

    fn recv(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<Option<super::IcmpResponse>, Box<dyn std::error::Error>> {
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: self.socket as u64,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, self.socket, &mut ev) } < 0 {
            unsafe { libc::close(epoll_fd) };
            return Err(std::io::Error::last_os_error())?;
        }

        unsafe {
            let mut evs: [libc::epoll_event; 1] = std::mem::zeroed();

            let timeout_millis = timeout.as_millis();
            let result = libc::epoll_wait(
                epoll_fd,
                evs.as_mut_ptr(),
                evs.len() as i32,
                timeout_millis as i32,
            );
            if result < 0 {
                libc::close(epoll_fd);
                let last_error = std::io::Error::last_os_error();
                return match last_error.kind() {
                    std::io::ErrorKind::Interrupted => Ok(None),
                    _ => Err(last_error)?,
                };
            }

            if result == 0 {
                libc::close(epoll_fd);
                return Ok(None);
            }
        }

        unsafe {
            libc::close(epoll_fd);
        }

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
                addr.as_mut(),
                addrlen_ptr,
            )
        };
        let rxtime = std::time::Instant::now();

        if recvfrom_result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }

        match self.target_sa {
            SocketAddr::V4(_) => Ok(super::parse_icmp_packet(rxtime, addr.try_into()?, &buf)),
            SocketAddr::V6(_) => Ok(super::parse_icmpv6_packet(rxtime, addr.try_into()?, &buf)),
        }
    }
}

impl Drop for PingProtocol {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.socket);
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
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x02, 0x20, 0x6c, 0x34, 0x00, 0x00,
            0x00, 0x01,
        ];
        let addr = libc::in6_addr::from_octets(&octets);
        assert_eq!(addr.s6_addr, octets);
    }
}
