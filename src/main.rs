mod sockaddr;

use std::{env, net};

use sockaddr::SockAddr;

struct PingProtocol {
    socket: i32,
    target: SockAddr,
    target_sa: net::SocketAddr,
}

impl PingProtocol {
    fn new(target_sa: net::SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let target = SockAddr::from(target_sa);
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
                self.target.as_ref(),
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
