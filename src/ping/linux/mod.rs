use std::net::SocketAddr;

use super::sockaddr::SockAddr;

pub mod types {
    pub use libc::sockaddr;
    pub use libc::sockaddr_in;
    pub use libc::sockaddr_in6;
    pub const AF_INET: u16 = libc::AF_INET as u16;
    pub const AF_INET6: u16 = libc::AF_INET6 as u16;
    pub type AddressFamily = u16;
    pub use super::FromOctets;
    pub use libc::in6_addr;
    pub use libc::in_addr;
}

pub struct PingProtocol {
    socket: i32,
    target: SockAddr,
    target_sa: SocketAddr,
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

impl PingProtocol {
    pub fn new(target: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
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
        })
    }

    pub fn send(&self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        let mut icmp_packet = [0u8; 64];
        let code = match self.target_sa {
            SocketAddr::V4(_) => 0x08,
            SocketAddr::V6(_) => 0x80,
        };
        let icmp_prefix: [u8; 16] = [code, 0, 0, 0, 0, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7];
        icmp_packet[0..16].copy_from_slice(&icmp_prefix);
        icmp_packet[4..6].copy_from_slice(&sequence.to_be_bytes());
        icmp_packet[6..8].copy_from_slice(&sequence.to_be_bytes());
        icmp_packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

        let buf = &icmp_packet as *const u8 as *const libc::c_void;
        println!("socket = {}", self.socket);
        println!("buf = {:?}", &icmp_packet);
        println!("icmp_packet.len() = {}", icmp_packet.len());
        println!("self.target.family = {:?}", self.target.sa_family());
        println!("self.target.as_ref() = {:?}", unsafe {
            &self.target.sin6.sin6_addr.s6_addr
        });
        println!(
            "std::mem::size_of::<SockAddr>() = {}",
            std::mem::size_of::<SockAddr>() as u32
        );
        let result = unsafe {
            libc::sendto(
                self.socket,
                buf,
                icmp_packet.len(),
                0,
                self.target.as_ref(),
                std::mem::size_of::<SockAddr>() as u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn recv(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<super::PingResponse>, Box<dyn std::error::Error>> {
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: self.socket as u64,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, self.socket, &mut ev) } < 0 {
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
                let err = std::io::Error::last_os_error();
                libc::close(epoll_fd);
                return Err(err)?;
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
        let rx_time = std::time::Instant::now();
        let identifier = u16::from_be_bytes(buf[4..6].try_into().unwrap());
        let sequence = u16::from_be_bytes(buf[6..8].try_into().unwrap());
        let timestamp = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        if recvfrom_result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(Some((
            addr.try_into()?,
            identifier,
            sequence,
            timestamp,
            rx_time,
        )))
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
