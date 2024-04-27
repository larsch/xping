mod sockaddr;

use std::net::SocketAddr;

use sockaddr::SockAddr;

pub struct PingProtocol {
    socket: i32,
    target: SockAddr,
    target_sa: SocketAddr,
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

    pub fn send(&self) -> Result<(), std::io::Error> {
        let mut icmp_packet: [u8; 192] = [0; 192];
        let code = match self.target_sa {
            SocketAddr::V4(_) => 0x08,
            SocketAddr::V6(_) => 0x80,
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
                self.target.as_ref(),
                std::mem::size_of::<SockAddr>() as u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn recv(&self) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
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
        if recvfrom_result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(Some(addr.try_into()?))
    }
}

impl Drop for PingProtocol {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.socket);
        }
    }
}
