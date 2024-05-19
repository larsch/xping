mod cmsghdr;
pub mod icmp;

use cmsghdr::*;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    process::abort,
    time::{Duration, Instant},
};

pub mod types {
    use windows::Win32::Networking::WinSock;
    pub use WinSock::AF_INET;
    pub use WinSock::AF_INET6;
    pub use WinSock::IN6_ADDR as in6_addr;
    pub use WinSock::IN_ADDR as in_addr;
    pub use WinSock::SOCKADDR as sockaddr;
    pub use WinSock::SOCKADDR_IN as sockaddr_in;
    pub use WinSock::SOCKADDR_IN6 as sockaddr_in6;
    pub type AddressFamily = WinSock::ADDRESS_FAMILY;
    pub use super::{AsIpv4Addr, AsIpv6Addr, FromOctets};
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<super::IcmpMessage> {
    let ip_header_length = ((packet[0] & 0x0F) * 4) as usize;
    let icmp_packet = &packet[ip_header_length..];
    let ip_proto = packet[9];
    if ip_proto == 1 {
        super::parse_icmp_packet(icmp_packet)
    } else {
        None
    }
}

pub trait FromOctets {
    fn from_octets(octets: &[u8]) -> Self;
}

impl FromOctets for WinSock::IN_ADDR {
    fn from_octets(octets: &[u8]) -> Self {
        WinSock::IN_ADDR {
            S_un: WinSock::IN_ADDR_0 {
                S_un_b: WinSock::IN_ADDR_0_0 {
                    s_b1: octets[0],
                    s_b2: octets[1],
                    s_b3: octets[2],
                    s_b4: octets[3],
                },
            },
        }
    }
}

impl FromOctets for WinSock::IN6_ADDR {
    fn from_octets(octets: &[u8]) -> Self {
        WinSock::IN6_ADDR {
            u: WinSock::IN6_ADDR_0 {
                Byte: octets.try_into().unwrap(),
            },
        }
    }
}

pub trait AsIpv4Addr {
    fn as_ipv4addr(&self) -> Ipv4Addr;
}

impl AsIpv4Addr for WinSock::IN_ADDR {
    fn as_ipv4addr(&self) -> Ipv4Addr {
        let octets = unsafe { self.S_un.S_un_b };
        Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4)
    }
}

pub trait FromIpv4Addr {
    fn from_ipv4addr(ip: &Ipv4Addr) -> Self;
}

impl FromIpv4Addr for WinSock::IN_ADDR {
    fn from_ipv4addr(ip: &Ipv4Addr) -> Self {
        WinSock::IN_ADDR {
            S_un: WinSock::IN_ADDR_0 {
                S_un_b: WinSock::IN_ADDR_0_0 {
                    s_b1: ip.octets()[0],
                    s_b2: ip.octets()[1],
                    s_b3: ip.octets()[2],
                    s_b4: ip.octets()[3],
                },
            },
        }
    }
}

// pub trait FromIpv6Addr {
//     fn from_ipv6addr(ip: &Ipv6Addr) -> Self;
// }

// impl FromIpv6Addr for WinSock::IN6_ADDR {
//     fn from_ipv6addr(ip: &Ipv6Addr) -> Self {
//         let octets = ip.octets();
//         WinSock::IN6_ADDR {
//             u: WinSock::IN6_ADDR_0 {
//                 Byte: octets,
//             },
//         }
//     }
// }

pub trait AsIpv6Addr {
    fn as_ipv6addr(&self) -> Ipv6Addr;
}

impl AsIpv6Addr for WinSock::IN6_ADDR {
    fn as_ipv6addr(&self) -> Ipv6Addr {
        let a: [u16; 8] = unsafe { self.u.Word };
        Ipv6Addr::new(
            u16::from_be(a[0]),
            u16::from_be(a[1]),
            u16::from_be(a[2]),
            u16::from_be(a[3]),
            u16::from_be(a[4]),
            u16::from_be(a[5]),
            u16::from_be(a[6]),
            u16::from_be(a[7]),
        )
    }
}

use libc::c_void;
use windows::{
    core::PSTR,
    Win32::{
        Foundation::HANDLE,
        Networking::WinSock::{self, WSACloseEvent, WSAGetLastError, WSAIoctl, SOCKET_ERROR},
        System::IO::{CancelIoEx, OVERLAPPED},
    },
};

pub struct PingProtocol {
    socket: WinSock::SOCKET,
    send_packet: Vec<u8>,
    recv_overlapped: OVERLAPPED,
    recv_from: super::sockaddr::SockAddr,
    recv_fromlen: i32,
    recv_buffer: [u8; 1500],
    target: SocketAddr,
    length: usize,
    wsarecvmsg: WinSock::LPFN_WSARECVMSG,
    control_buffer: [u8; 512],
}

impl Drop for PingProtocol {
    fn drop(&mut self) {
        if self.recv_overlapped.hEvent != HANDLE::default() {
            unsafe {
                let handle = HANDLE(self.socket.0 as isize);
                CancelIoEx(handle, Some(&self.recv_overlapped)).unwrap();
            }
        }
        unsafe {
            let close_result = WinSock::closesocket(self.socket);
            assert!(close_result == 0, "Failed to close socket");
        }
    }
}

impl super::Pinger for PingProtocol {
    fn new(target: SocketAddr, length: usize) -> Result<Self, std::io::Error> {
        unsafe {
            let mut wsadata = WinSock::WSADATA::default();
            const VERSION_REQUESTED: u16 = 0x0202;
            let result = WinSock::WSAStartup(VERSION_REQUESTED, &mut wsadata);
            if result != 0 {
                return Err(std::io::Error::from_raw_os_error(result));
            }
        }

        let (family, proto) = match target {
            SocketAddr::V4(_) => (WinSock::AF_INET, WinSock::IPPROTO_ICMP),
            SocketAddr::V6(_) => (WinSock::AF_INET6, WinSock::IPPROTO_ICMPV6),
        };

        let socket = unsafe { WinSock::WSASocketW(family.0 as i32, WinSock::SOCK_RAW.0, proto.0, None, 0, WinSock::WSA_FLAG_OVERLAPPED) };
        if socket == WinSock::INVALID_SOCKET {
            return Err(std::io::Error::last_os_error());
        }

        let mut recvmsg_function_pointer: *const std::ffi::c_void = std::ptr::null_mut();
        let mut bytes_returned = 0u32;
        let result = unsafe {
            WSAIoctl(
                socket,
                WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                Some(&WinSock::WSAID_WSARECVMSG as *const windows::core::GUID as *const c_void),
                std::mem::size_of::<windows::core::GUID>() as u32,
                Some(&mut recvmsg_function_pointer as *mut *const c_void as *mut c_void),
                std::mem::size_of::<*const c_void>() as u32,
                &mut bytes_returned,
                None,
                None,
            )
        };
        // convert recvmsg_function_pointer to WinSock::LPFN_WSARECVMSG

        if result == WinSock::SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        let recvmsg_function_pointer =
            unsafe { std::mem::transmute::<*const std::ffi::c_void, WinSock::LPFN_WSARECVMSG>(recvmsg_function_pointer) };

        let ping = PingProtocol {
            socket,
            send_packet: Vec::with_capacity(8 + length),
            recv_overlapped: Default::default(),
            recv_buffer: [0u8; 1500],
            target,
            recv_from: Default::default(),
            recv_fromlen: 0,
            length,
            wsarecvmsg: recvmsg_function_pointer,
            control_buffer: [0u8; 512],
        };

        let enabled: u32 = 1;
        ping.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_RECVTTL, &enabled)?;
        ping.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_HOPLIMIT, &enabled)?;

        Ok(ping)
    }

    fn set_ttl(&mut self, ttl: u8) -> Result<(), std::io::Error> {
        let ttl = ttl as u32;
        if self.target.is_ipv4() {
            self.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_TTL, &ttl)?;
            self.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_MULTICAST_TTL, &ttl)?;
        } else {
            self.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_UNICAST_HOPS, &ttl)?;
            self.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_MULTICAST_HOPS, &ttl)?;
        }
        Ok(())
    }

    fn send(&mut self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        let icmp_type = match self.target {
            SocketAddr::V4(_) => 8,
            SocketAddr::V6(_) => 128,
        };
        let code = 0;
        let id = sequence;
        self.send_packet.resize(8 + self.length, 0u8);
        super::construct_icmp_packet(&mut self.send_packet, icmp_type, code, id, sequence, timestamp);
        // let mut packet16 = [0u16; self.length];
        // let packet: &mut [u8; 32] = unsafe { std::mem::transmute(&mut packet16) };
        let packet = &mut self.send_packet;

        // packet[self.length - 1] ^= 0xffu8;

        // Create PSTR/WSABUF for icmp packet
        let packet_pstr = PSTR::from_raw(packet.as_mut_ptr());
        let packet_wsabuf = [WinSock::WSABUF {
            len: (self.length + 8) as u32,
            buf: packet_pstr,
        }];

        let mut bytes_sent: u32 = 0;

        let target_sa: super::sockaddr::SockAddr = self.target.into();

        let result = unsafe {
            WinSock::WSASendTo(
                self.socket,
                &packet_wsabuf,
                Some(&mut bytes_sent),
                0,
                Some(target_sa.as_ref()),
                std::mem::size_of::<super::sockaddr::SockAddr>() as i32,
                None,
                None,
            )
        };

        if result == WinSock::SOCKET_ERROR {
            let err = unsafe { WSAGetLastError() };
            return Err(std::io::Error::from_raw_os_error(err.0 as i32));
        }

        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<super::IcmpResult, std::io::Error> {
        let mut recv_wsabuf = [WinSock::WSABUF {
            len: self.recv_buffer.len() as u32,
            buf: PSTR::from_raw(self.recv_buffer.as_mut_ptr()),
        }];
        let mut bytes_received = 0u32;

        // let mut recv_sockaddr = WinSock::SOCKADDR::default();
        self.recv_fromlen = std::mem::size_of::<crate::ping::sockaddr::SockAddr>() as i32;

        let mut flags = 0u32;

        if self.recv_overlapped.hEvent == HANDLE::default() {
            // Overlapped operation not started yet

            self.recv_overlapped.hEvent = unsafe { WinSock::WSACreateEvent() }.unwrap();

            let result = if self.wsarecvmsg.is_some() {
                let mut msg = WinSock::WSAMSG {
                    name: self.recv_from.as_mut(),
                    namelen: self.recv_fromlen,
                    lpBuffers: recv_wsabuf.as_mut_ptr(),
                    dwBufferCount: 1,
                    Control: WinSock::WSABUF {
                        len: self.control_buffer.len() as u32,
                        buf: PSTR::from_raw(self.control_buffer.as_mut_ptr()),
                    },
                    dwFlags: 0,
                };
                unsafe { (self.wsarecvmsg.unwrap())(self.socket, &mut msg, &mut bytes_received, &mut self.recv_overlapped, None) }
            } else {
                unsafe {
                    WinSock::WSARecvFrom(
                        self.socket,
                        &recv_wsabuf,
                        Some(&mut bytes_received as *mut u32),
                        &mut flags as *mut u32,
                        Some(self.recv_from.as_mut()),
                        Some(&mut self.recv_fromlen),
                        Some(&mut self.recv_overlapped as *mut OVERLAPPED),
                        None,
                    )
                }
            };

            match result {
                0 => {
                    println!("completed immediately");

                    // The operation completed immediately
                    unsafe { WinSock::WSACloseEvent(self.recv_overlapped.hEvent) }.unwrap();

                    self.recv_overlapped.hEvent = HANDLE::default();

                    return self.complete_recv(self.recv_from.try_into(), bytes_received);
                }
                SOCKET_ERROR => {
                    // The operation failed (or overlapped operation is pending)
                    let err = unsafe { WinSock::WSAGetLastError() };
                    if err != WinSock::WSA_IO_PENDING {
                        return Err(std::io::Error::from_raw_os_error(err.0 as i32));
                    }
                }
                _ => {
                    abort();
                }
            }
        }

        let timeout = timeout.as_millis() as u32;

        // An overlapped operation has now been started
        let rc = unsafe { WinSock::WSAWaitForMultipleEvents(&[self.recv_overlapped.hEvent], true, timeout, true) };

        match rc.0 {
            WinSock::WSA_WAIT_TIMEOUT => Ok(super::IcmpResult::Timeout),
            WinSock::WSA_WAIT_FAILED => Err(std::io::Error::from_raw_os_error(unsafe { WinSock::WSAGetLastError() }.0 as i32)),
            0 => {
                let mut flags = 0u32;
                unsafe {
                    WinSock::WSAGetOverlappedResult(
                        self.socket,
                        &self.recv_overlapped,
                        &mut bytes_received as *mut u32,
                        false,
                        &mut flags as *mut u32,
                    )
                }
                .unwrap();

                unsafe { WSACloseEvent(self.recv_overlapped.hEvent) }.unwrap();
                self.recv_overlapped.hEvent = HANDLE::default();

                let sa: Result<SocketAddr, String> = self.recv_from.try_into();

                self.complete_recv(sa, bytes_received)
            }
            _ => panic!(),
        }
    }
}

impl PingProtocol {
    fn setsockopt<T: Sized, N: TryInto<i32>>(&self, level: N, optname: i32, optval: &T) -> Result<(), std::io::Error>
    where
        N::Error: std::fmt::Debug,
    {
        let result = unsafe {
            WinSock::setsockopt(
                self.socket,
                level.try_into().unwrap(),
                optname,
                Some(std::slice::from_raw_parts(
                    optval as *const T as *const u8,
                    std::mem::size_of::<T>(),
                )),
            )
        };
        if result == SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn complete_recv_from(&mut self, recv_fromlen: usize) -> Option<super::IcmpMessage> {
        let packet = &self.recv_buffer[0..recv_fromlen];
        match self.target {
            SocketAddr::V4(_) => parse_ipv4_packet(packet),
            SocketAddr::V6(_) => super::parse_icmpv6_packet(packet),
        }
    }

    fn complete_recv(&mut self, sa: Result<SocketAddr, String>, bytes_received: u32) -> Result<super::IcmpResult, std::io::Error> {
        let mut ttl: Option<u32> = None;

        if self.wsarecvmsg.is_some() {
            // Need to set WSAMSG up again, since the one used previously is
            // possible no longer available. Only the Control member is used.
            let msg = WinSock::WSAMSG {
                Control: WinSock::WSABUF {
                    len: self.control_buffer.len() as u32,
                    buf: PSTR::from_raw(self.control_buffer.as_mut_ptr()),
                },
                ..Default::default()
            };

            // let cmsghdr: *const WinSock::CMSGHDR = self.control_buffer.as_ptr() as *const WinSock::CMSGHDR;
            let mut cmsg = cmsg_firsthdr(&msg);
            while !cmsg.is_null() {
                let cmsg_type = unsafe { (*cmsg).cmsg_type };
                match cmsg_type {
                    WinSock::IP_TTL => {
                        ttl = Some(unsafe { *(cmsg_data(cmsg) as *const u32) });
                    }
                    WinSock::IPV6_HOPLIMIT => {
                        debug_assert!(
                            unsafe { (*cmsg).cmsg_len } as usize == std::mem::size_of::<WinSock::CMSGHDR>() + std::mem::size_of::<u32>()
                        );
                        ttl = Some(unsafe { *(cmsg_data(cmsg) as *const u32) });
                    }
                    _ => {
                        #[cfg(debug_assertions)]
                        panic!("Unknown cmsg_type: {:x}", cmsg_type);
                    }
                }

                cmsg = cmsg_nxthdr(&msg, cmsg);
            }
            // println!("cmsghdr.first() = {:p}", cmsghdr.first());
        }

        Ok(super::IcmpResult::IcmpPacket(super::IcmpPacket {
            addr: sa.unwrap(),
            message: self.complete_recv_from(bytes_received as usize).unwrap(),
            time: Instant::now(),
            recvttl: ttl,
        }))
    }
}

// fn last_wsa_error() -> String {
//     let error_id = unsafe { WSAGetLastError() };
//     lookup_error(error_id.0 as u32).unwrap()
// }

// fn lookup_error(error_id: u32) -> Result<String, std::string::FromUtf16Error> {
//     let mut str = PWSTR::null();
//     let error_message = unsafe {
//         FormatMessageW(
//             Debug::FORMAT_MESSAGE_ALLOCATE_BUFFER
//                 | Debug::FORMAT_MESSAGE_FROM_SYSTEM
//                 | Debug::FORMAT_MESSAGE_IGNORE_INSERTS,
//             None,
//             error_id,
//             0,
//             #[allow(clippy::crosspointer_transmute)] // This is safe and required by the API
//             std::mem::transmute(&mut str as *mut PWSTR),
//             0,
//             None,
//         );
//         let error_message = str.to_string();
//         windows::Win32::Foundation::LocalFree(HLOCAL(str.as_ptr() as *mut c_void));
//         error_message
//     };
//     Ok(error_message.unwrap())
// }

#[cfg(test)]
mod test {
    use super::FromOctets;

    #[test]
    fn test_from_octets() {
        let octets = [192, 168, 1, 1];
        let addr = super::types::in_addr::from_octets(&octets);
        unsafe {
            assert_eq!(addr.S_un.S_un_b.s_b1, 192);
            assert_eq!(addr.S_un.S_un_b.s_b2, 168);
            assert_eq!(addr.S_un.S_un_b.s_b3, 1);
            assert_eq!(addr.S_un.S_un_b.s_b4, 1);
        }
    }

    #[test]
    fn test_from_octets_v6() {
        let octets = [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8];
        let addr = super::types::in6_addr::from_octets(&octets);
        unsafe {
            assert_eq!(addr.u.Byte, [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]);
        }
    }
}
