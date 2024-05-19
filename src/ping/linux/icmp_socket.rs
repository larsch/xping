use crate::ping::sockaddr::SockAddr;
use std::net::SocketAddr;
use super::IcmpExtendedSocketErr;

pub struct IcmpSocketApi {
    socket: i32,
    target: SockAddr,
    target_sa: SocketAddr,
    packet: Vec<u8>,
    length: usize,
}

impl IcmpSocketApi {
    fn configure(&mut self) -> Result<(), std::io::Error> {
        let enabled: libc::c_int = 1;
        if self.target_sa.is_ipv4() {
            self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVERR, &enabled)?;
            self.setsockopt(libc::IPPROTO_IP, libc::IP_RECVTTL, &enabled)?;
        } else if self.target_sa.is_ipv6() {
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVERR, &enabled)?;
            self.setsockopt(libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, &enabled).unwrap();
        }
        // TODO: self.setsockopt(libc::SOL_SOCKET, libc::SO_TIMESTAMP, &enabled)?;
        Ok(())
    }

    fn setsockopt<T: Sized>(&mut self, level: libc::c_int, name: libc::c_int, optval: &T) -> Result<(), std::io::Error> {
        let result = unsafe {
            libc::setsockopt(
                self.socket,
                level,
                name,
                optval as *const T as *const std::ffi::c_void,
                std::mem::size_of::<T>() as u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(())
    }
}

impl crate::ping::IcmpApi for IcmpSocketApi {
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
        let socket = unsafe { libc::socket(target_family, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, ipproto) };
        if socket < 0 {
            return Err(std::io::Error::last_os_error())?;
        }

        // IP_RETOPTS
        let optval = 1;
        let result = unsafe {
            libc::setsockopt(
                socket,
                libc::SOL_IP,
                libc::IP_RETOPTS,
                &optval as *const i32 as *const std::ffi::c_void,
                std::mem::size_of::<std::ffi::c_int>() as u32,
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }

        let result = unsafe { libc::connect(socket, sockaddr.as_ref(), std::mem::size_of::<SockAddr>() as u32) };
        if result < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        let mut ping = Self {
            socket,
            target: sockaddr,
            target_sa: target,
            packet: vec![0u8; length + 8],
            length,
        };
        match ping.configure() {
            Ok(_) => Ok(ping),
            Err(e) => {
                unsafe { libc::close(socket) };
                Err(e)
            }
        }
    }

    fn send(&mut self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        self.packet.resize(self.length + 8, 0u8);
        let icmp_type = match self.target_sa {
            SocketAddr::V4(_) => 0x08,
            SocketAddr::V6(_) => 0x80,
        };
        let code = 0;
        let id = sequence;
        crate::ping::construct_icmp_packet(&mut self.packet, icmp_type, code, id, sequence, timestamp);

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

    fn recv(&mut self, timeout: std::time::Duration) -> Result<crate::ping::IcmpResult, std::io::Error> {
        let epoll_fd = unsafe { libc::epoll_create1(0) };
        if epoll_fd < 0 {
            return Err(std::io::Error::last_os_error())?;
        }
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLERR) as u32,
            u64: self.socket as u64,
        };
        if unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, self.socket, &mut ev) } < 0 {
            unsafe { libc::close(epoll_fd) };
            return Err(std::io::Error::last_os_error())?;
        }

        unsafe {
            let mut evs: [libc::epoll_event; 1] = std::mem::zeroed();

            let timeout_millis = timeout.as_millis();
            let result = libc::epoll_wait(epoll_fd, evs.as_mut_ptr(), evs.len() as i32, timeout_millis as i32);
            if result < 0 {
                libc::close(epoll_fd);
                let last_error = std::io::Error::last_os_error();
                return match last_error.kind() {
                    std::io::ErrorKind::Interrupted => Ok(crate::ping::IcmpResult::Interrupted),
                    _ => Err(last_error)?,
                };
            }

            if result == 0 {
                libc::close(epoll_fd);
                return Ok(crate::ping::IcmpResult::Timeout);
            }
        }

        unsafe {
            libc::close(epoll_fd);
        }

        let mut buf = [0u8; 65536];
        let buf_ptr = &mut buf as *mut u8 as *mut libc::c_void;
        // let flags = 0;
        let mut addr: SockAddr = unsafe { std::mem::zeroed() };
        // let mut addr_len = std::mem::size_of::<SockAddr>() as u32;
        // let addrlen_ptr = &mut addr_len as *mut u32;

        let mut extended_error = None;
        let mut recvmsg_flags = 0;
        let mut orig_error = None;

        #[allow(unused_assignments)]
        let mut rxtime = None;

        let mut recvttl = None;

        #[allow(unused_assignments)]
        let mut received_bytes: usize = 0;

        loop {
            let iovec = libc::iovec {
                iov_base: buf_ptr,
                iov_len: buf.len(),
            };
            // let mut ext: libc::sock_extended_err = unsafe { std::mem::zeroed() };
            let mut controlmsg = [0u8; 512];
            let mut msghdr = libc::msghdr {
                msg_name: addr.as_mut() as *mut libc::sockaddr as *mut libc::c_void,
                msg_namelen: std::mem::size_of::<SockAddr>() as u32,
                msg_iov: &iovec as *const libc::iovec as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: controlmsg.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: controlmsg.len(),
                msg_flags: 0,
            };
            // println!("msghdr.msg_name = {:p}", msghdr.msg_name);
            // println!("msghdr.msg_namelen = {}", msghdr.msg_namelen);
            // println!("msghdr.msg_iov = {:p}", msghdr.msg_iov);
            // println!("msghdr.msg_iovlen = {}", msghdr.msg_iovlen);
            // println!("msghdr.msg_control = {:p}", msghdr.msg_control);
            // println!("msghdr.msg_controllen = {}", msghdr.msg_controllen);
            // println!("msghdr.msg_flags = {}", msghdr.msg_flags);
            // println!("{:08x}", buf_ptr as usize);
            let result = unsafe { libc::recvmsg(self.socket, &mut msghdr, recvmsg_flags) };
            rxtime = Some(std::time::Instant::now());

            if result < 0 {
                if recvmsg_flags == 0 {
                    orig_error = Some(std::io::Error::last_os_error());
                    recvmsg_flags = libc::MSG_ERRQUEUE;
                    continue;
                } else {
                    return Err(std::io::Error::last_os_error())?;
                }
            } else {
                received_bytes = result as usize;
                let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
                while !cmsg.is_null() {
                    let cmsg_type = unsafe { (*cmsg).cmsg_type };

                    let dataptr = unsafe { libc::CMSG_DATA(cmsg) };
                    let data_offset = unsafe { dataptr.offset_from(cmsg as *const u8) } as usize;
                    let data_len = unsafe { (*cmsg).cmsg_len } as usize - data_offset;
                    let data = unsafe { std::slice::from_raw_parts(dataptr, data_len) };

                    match cmsg_type {
                        libc::IP_TTL => {
                            if data.len() >= std::mem::size_of::<u32>() {
                                let ttl = u32::from_ne_bytes(data.try_into().unwrap());
                                recvttl = Some(ttl);
                            }
                        }
                        libc::IP_RECVERR | libc::IPV6_RECVERR => {
                            if data.len() >= std::mem::size_of::<libc::sock_extended_err>() {
                                let serr = unsafe { &*(dataptr as *const libc::sock_extended_err) };
                                dbg!("srr: {:?}", serr);
                                if serr.ee_origin == libc::SO_EE_ORIGIN_ICMP || serr.ee_origin == libc::SO_EE_ORIGIN_ICMP6 {
                                    extended_error = Some(IcmpExtendedSocketErr::from(serr));
                                }
                            }
                        }
                        libc::IPV6_HOPLIMIT => {
                            if data.len() >= std::mem::size_of::<u32>() {
                                let ttl = u32::from_ne_bytes(data.try_into().unwrap());
                                recvttl = Some(ttl);
                            }
                        }
                        _ => todo!("{:?}", cmsg_type),
                    }
                    cmsg = unsafe { libc::CMSG_NXTHDR(&msghdr, cmsg) };
                }
                break;
            }
        }

        if recvmsg_flags & libc::MSG_ERRQUEUE == 0 {
            let packet = &buf[..received_bytes.max(0)];
            Ok(crate::ping::IcmpResult::IcmpPacket(crate::ping::IcmpPacket {
                addr: addr.try_into().map_err(|_| std::io::Error::from_raw_os_error(0))?,
                message: match self.target_sa {
                    SocketAddr::V4(_) => crate::ping::parse_icmp_packet(packet).unwrap(),
                    SocketAddr::V6(_) => crate::ping::parse_icmpv6_packet(packet).unwrap(),
                },
                time: rxtime.unwrap(),
                recvttl,
            }))
        } else {
            let original_message = &buf[..received_bytes];

            if let Some(extended_error) = extended_error {
                Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                    addr: Some(addr.try_into().map_err(|_| std::io::Error::from_raw_os_error(0))?),
                    error: Some(std::io::Error::from_raw_os_error(extended_error.errno)),
                    icmp_type: Some(extended_error.icmp_type),
                    icmp_code: Some(extended_error.icmp_code),
                    offender: extended_error.offender,
                    time: rxtime.unwrap(),
                    original_message: match self.target_sa {
                        SocketAddr::V4(_) => crate::ping::parse_icmp_packet(original_message),
                        SocketAddr::V6(_) => crate::ping::parse_icmpv6_packet(original_message),
                    },
                }))
            } else {
                Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                    addr: Some(addr.try_into().map_err(|_| std::io::Error::from_raw_os_error(0))?),
                    error: Some(orig_error.unwrap()),
                    icmp_type: None,
                    icmp_code: None,
                    offender: None,
                    time: rxtime.unwrap(),
                    original_message: match self.target_sa {
                        SocketAddr::V4(_) => crate::ping::parse_icmp_packet(original_message),
                        SocketAddr::V6(_) => crate::ping::parse_icmpv6_packet(original_message),
                    },
                }))
            }
        }
    }

    fn set_ttl(&mut self, ttl: u8) -> Result<(), std::io::Error> {
        let ttl: libc::c_int = ttl as libc::c_int;
        if self.target_sa.is_ipv4() {
            self.setsockopt(libc::SOL_IP, libc::IP_MULTICAST_TTL, &ttl)?;
            self.setsockopt(libc::SOL_IP, libc::IP_TTL, &ttl)?;
        }
        if self.target_sa.is_ipv6() {
            self.setsockopt(libc::SOL_IPV6, libc::IPV6_MULTICAST_HOPS, &ttl)?;
            self.setsockopt(libc::SOL_IPV6, libc::IPV6_UNICAST_HOPS, &ttl)?;
        }
        Ok(())
    }
}

impl Drop for IcmpSocketApi {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.socket);
        }
    }
}
