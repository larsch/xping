use std::net::SocketAddr;

use crate::ping::{sockaddr::SockAddr, IcmpPacket, IcmpResult};

use super::cmsghdr::*;

use libc::c_void;
use windows::{
    core::PSTR,
    Win32::{
        Foundation::HANDLE,
        Networking::WinSock,
        System::IO::{CancelIoEx, OVERLAPPED},
    },
};

pub struct IcmpSocketApi {
    socket: WinSock::SOCKET,
    send_packet: Vec<u8>,
    recv_overlapped: OVERLAPPED,
    recv_from: SockAddr,
    recv_fromlen: i32,
    recv_buffer: [u8; 1500],
    target: SocketAddr,
    length: usize,
    wsarecvmsg: WinSock::LPFN_WSARECVMSG,
    control_buffer: [u8; 512],
}

impl Drop for IcmpSocketApi {
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

impl crate::ping::IcmpApi for IcmpSocketApi {
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
            WinSock::WSAIoctl(
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

        let ping = IcmpSocketApi {
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
        crate::ping::construct_icmp_packet(&mut self.send_packet, icmp_type, code, id, sequence, timestamp);
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

        let target_sa: SockAddr = self.target.into();

        let result = unsafe {
            WinSock::WSASendTo(
                self.socket,
                &packet_wsabuf,
                Some(&mut bytes_sent),
                0,
                Some(target_sa.as_ref()),
                std::mem::size_of::<SockAddr>() as i32,
                None,
                None,
            )
        };

        if result == WinSock::SOCKET_ERROR {
            let err = unsafe { WinSock::WSAGetLastError() };
            return Err(std::io::Error::from_raw_os_error(err.0 as i32));
        }

        Ok(())
    }

    fn recv(&mut self, timeout: std::time::Duration) -> Result<IcmpResult, std::io::Error> {
        let mut recv_wsabuf = [WinSock::WSABUF {
            len: self.recv_buffer.len() as u32,
            buf: PSTR::from_raw(self.recv_buffer.as_mut_ptr()),
        }];
        let mut bytes_received = 0u32;

        // let mut recv_sockaddr = WinSock::SOCKADDR::default();
        self.recv_fromlen = std::mem::size_of::<SockAddr>() as i32;

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
                    // The operation completed immediately
                    unsafe { WinSock::WSACloseEvent(self.recv_overlapped.hEvent) }.unwrap();

                    self.recv_overlapped.hEvent = HANDLE::default();

                    return self.complete_recv(self.recv_from.try_into(), bytes_received);
                }
                WinSock::SOCKET_ERROR => {
                    // The operation failed (or overlapped operation is pending)
                    let err = unsafe { WinSock::WSAGetLastError() };
                    if err != WinSock::WSA_IO_PENDING {
                        return Err(std::io::Error::from_raw_os_error(err.0 as i32));
                    }
                }
                _ => unreachable!("WSARecvFrom returned unexpected value"),
            }
        }

        let timeout = timeout.as_millis() as u32;

        // An overlapped operation has now been started
        let rc = unsafe { WinSock::WSAWaitForMultipleEvents(&[self.recv_overlapped.hEvent], true, timeout, true) };

        match rc.0 {
            WinSock::WSA_WAIT_TIMEOUT => Ok(IcmpResult::Timeout),
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

                unsafe { WinSock::WSACloseEvent(self.recv_overlapped.hEvent) }.unwrap();
                self.recv_overlapped.hEvent = HANDLE::default();

                let sa: Result<SocketAddr, String> = self.recv_from.try_into();

                self.complete_recv(sa, bytes_received)
            }
            _ => panic!(),
        }
    }
}

impl IcmpSocketApi {
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
        if result == WinSock::SOCKET_ERROR {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn complete_recv_from(&mut self, recv_fromlen: usize) -> Option<crate::ping::IcmpMessage> {
        let packet = &self.recv_buffer[0..recv_fromlen];
        match self.target {
            SocketAddr::V4(_) => super::parse_ipv4_packet(packet),
            SocketAddr::V6(_) => crate::ping::parse_icmpv6_packet(packet),
        }
    }

    fn complete_recv(&mut self, sa: Result<SocketAddr, String>, bytes_received: u32) -> Result<IcmpResult, std::io::Error> {
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

        Ok(IcmpResult::IcmpPacket(IcmpPacket {
            addr: sa.unwrap(),
            message: self.complete_recv_from(bytes_received as usize).unwrap(),
            time: std::time::Instant::now(),
            recvttl: ttl,
        }))
    }
}
