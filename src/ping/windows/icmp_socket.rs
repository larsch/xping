use std::net::{IpAddr, SocketAddr};

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

struct IcmpSocket {
    socket: WinSock::SOCKET,
    overlapped: OVERLAPPED,
    recvfrom: SockAddr,
    recvfromlen: i32,
    recvbuffer: [u8; 1500],
    sendbuffer: Vec<u8>,
    wsarecvmsg: WinSock::LPFN_WSARECVMSG,
    controlbuffer: [u8; 512],
    wsamsg: WinSock::WSAMSG,
    has_sent: bool,
}

impl IcmpSocket {
    fn new(address_family: WinSock::ADDRESS_FAMILY, protocol: WinSock::IPPROTO) -> Result<Self, crate::ping::Error> {
        match unsafe {
            WinSock::WSASocketW(
                address_family.0 as i32,
                WinSock::SOCK_RAW.0,
                protocol.0,
                None,
                0,
                WinSock::WSA_FLAG_OVERLAPPED,
            )
        } {
            WinSock::INVALID_SOCKET => Err(std::io::Error::last_os_error())?,
            socket => Ok(IcmpSocket {
                socket,
                overlapped: OVERLAPPED::default(),
                recvfrom: Default::default(),
                recvfromlen: 0,
                recvbuffer: [0u8; 1500],
                sendbuffer: Vec::with_capacity(1500),
                wsarecvmsg: get_wsarecvmsg(socket)?,
                controlbuffer: [0u8; 512],
                wsamsg: Default::default(),
                has_sent: false,
            }),
        }
    }

    fn new_ipv4() -> Result<Self, crate::ping::Error> {
        let socket = Self::new(WinSock::AF_INET, WinSock::IPPROTO_ICMP)?;
        let enabled: u32 = 1;
        socket.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_RECVTTL, &enabled)?;
        Ok(socket)
    }

    fn new_ipv6() -> Result<Self, crate::ping::Error> {
        let socket = Self::new(WinSock::AF_INET6, WinSock::IPPROTO_ICMPV6)?;
        let enabled: u32 = 1;
        socket.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_HOPLIMIT, &enabled)?;
        Ok(socket)
    }

    fn setsockopt<T: Sized>(&self, level: i32, optname: i32, optval: &T) -> Result<(), crate::ping::Error> {
        let result = unsafe {
            WinSock::setsockopt(
                self.socket,
                level,
                optname,
                Some(std::slice::from_raw_parts(
                    optval as *const T as *const u8,
                    std::mem::size_of::<T>(),
                )),
            )
        };
        if result == WinSock::SOCKET_ERROR {
            return Err(std::io::Error::last_os_error())?;
        }
        Ok(())
    }

    fn send(&mut self, target: IpAddr, length: usize, sequence: u16, timestamp: u64) -> Result<(), crate::ping::Error> {
        let icmp_type = match target {
            IpAddr::V4(_) => 8,
            IpAddr::V6(_) => 128,
        };
        let code = 0;
        let id = sequence;
        self.sendbuffer.resize(8 + length, 0u8);
        crate::ping::construct_icmp_packet(&mut self.sendbuffer, icmp_type, code, id, sequence, timestamp);
        let packet = &mut self.sendbuffer;

        // Create PSTR/WSABUF for icmp packet
        let packet_pstr = PSTR::from_raw(packet.as_mut_ptr());
        let packet_wsabuf = [WinSock::WSABUF {
            len: (length + 8) as u32,
            buf: packet_pstr,
        }];

        let mut bytes_sent: u32 = 0;

        let target_sa: SockAddr = SocketAddr::new(target, 0).into();

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
            return Err(std::io::Error::from_raw_os_error(err.0 as i32))?;
        }

        self.has_sent = true;

        Ok(())
    }

    fn recv(&mut self) -> Result<Option<IcmpResult>, crate::ping::Error> {
        if !self.has_sent {
            // Trying to receive before sending causes WinSock to fail with
            // "invalid argument"
            return Ok(None);
        }

        let mut recv_wsabuf = [WinSock::WSABUF {
            len: self.recvbuffer.len() as u32,
            buf: PSTR::from_raw(self.recvbuffer.as_mut_ptr()),
        }];

        // let mut recv_sockaddr = WinSock::SOCKADDR::default();
        self.recvfromlen = std::mem::size_of::<SockAddr>() as i32;

        let mut flags = 0u32;
        let mut bytes_received = 0u32;

        if self.overlapped.hEvent == HANDLE::default() {
            self.overlapped.hEvent = unsafe { WinSock::WSACreateEvent() }.unwrap();
            let result = match self.wsarecvmsg {
                Some(wsarecvmsg_fn) => {
                    // According to the documentation, the WSARecvMsg is
                    // required to copy the WSAMSG structure before returning.
                    // However, this _appears_ to result in a crash (access
                    // violation or stack overflow). This goes away if we keep
                    // the WSAMSG structure on the heap.
                    // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms741687(v=vs.85)

                    self.wsamsg = WinSock::WSAMSG {
                        name: self.recvfrom.as_mut(),
                        namelen: self.recvfromlen,
                        lpBuffers: recv_wsabuf.as_mut_ptr(),
                        dwBufferCount: 1,
                        Control: WinSock::WSABUF {
                            len: self.controlbuffer.len() as u32,
                            buf: PSTR::from_raw(self.controlbuffer.as_mut_ptr()),
                        },
                        dwFlags: 0,
                    };
                    unsafe { wsarecvmsg_fn(self.socket, &mut self.wsamsg, &mut bytes_received, &mut self.overlapped, None) }
                }
                None => unsafe {
                    WinSock::WSARecvFrom(
                        self.socket,
                        &recv_wsabuf,
                        Some(&mut bytes_received as *mut _),
                        &mut flags as *mut u32,
                        Some(self.recvfrom.as_mut()),
                        Some(&mut self.recvfromlen),
                        Some(&mut self.overlapped as *mut _),
                        None,
                    )
                },
            };

            match result {
                0 => {
                    // The operation completed immediately
                    unsafe { WinSock::WSACloseEvent(self.overlapped.hEvent) }.unwrap();
                    self.overlapped.hEvent = HANDLE::default();
                    Ok(Some(self.complete_recv(self.recvfrom.try_into().unwrap(), bytes_received)?))
                }
                WinSock::SOCKET_ERROR => {
                    // The operation failed (or overlapped operation is pending)
                    let err = unsafe { WinSock::WSAGetLastError() };
                    if err != WinSock::WSA_IO_PENDING {
                        unsafe { WinSock::WSACloseEvent(self.overlapped.hEvent) }.unwrap();
                        self.overlapped.hEvent = HANDLE::default();
                        return Err(std::io::Error::from_raw_os_error(err.0 as i32))?;
                    }
                    Ok(None)
                }
                _ => unreachable!("WSARecvFrom returned unexpected value"),
            }
        } else {
            // Overlapped operation is already pending
            Ok(None)
        }
    }

    fn get_overlapped_result(&mut self) -> Result<IcmpResult, crate::ping::Error> {
        let mut flags = 0u32;
        let mut bytes_received = 0u32;

        unsafe {
            WinSock::WSAGetOverlappedResult(
                self.socket,
                &self.overlapped,
                &mut bytes_received as *mut u32,
                false,
                &mut flags as *mut u32,
            )
        }?;

        unsafe { WinSock::WSACloseEvent(self.overlapped.hEvent) }.unwrap();
        self.overlapped.hEvent = HANDLE::default();

        let sa: SocketAddr = self.recvfrom.try_into().unwrap();

        self.complete_recv(sa, bytes_received)
    }

    fn complete_recv_from(&mut self, target: IpAddr, bytes_received: usize) -> Option<crate::ping::IcmpMessage> {
        let packet = &self.recvbuffer[0..bytes_received];
        match target {
            IpAddr::V4(_) => super::parse_ipv4_packet(packet),
            IpAddr::V6(_) => crate::ping::parse_icmpv6_packet(packet),
        }
    }

    fn complete_recv(&mut self, sa: SocketAddr, bytes_received: u32) -> Result<IcmpResult, crate::ping::Error> {
        let mut ttl: Option<u32> = None;

        if self.wsarecvmsg.is_some() {
            // let cmsghdr: *const WinSock::CMSGHDR = self.control_buffer.as_ptr() as *const WinSock::CMSGHDR;
            let mut cmsg = cmsg_firsthdr(&self.wsamsg);
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
                    _ => unreachable!("Unexpected cmsg_type: {}", cmsg_type),
                }

                cmsg = cmsg_nxthdr(&self.wsamsg, cmsg);
            }
            // println!("cmsghdr.first() = {:p}", cmsghdr.first());
        }

        Ok(IcmpResult::IcmpPacket(IcmpPacket {
            addr: sa,
            message: self.complete_recv_from(sa.ip(), bytes_received as usize).unwrap(),
            time: std::time::Instant::now(),
            recvttl: ttl,
        }))
    }
}

pub struct IcmpSocketApi {
    socket4: Option<IcmpSocket>,
    socket6: Option<IcmpSocket>,
    ttl: Option<u8>,
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        if self.overlapped.hEvent != HANDLE::default() {
            unsafe {
                let handle = HANDLE(self.socket.0 as isize);
                CancelIoEx(handle, Some(&self.overlapped)).unwrap();
            }
        }
        unsafe {
            let close_result = WinSock::closesocket(self.socket);
            assert!(close_result == 0, "Failed to close socket");
        }
    }
}

impl crate::ping::IcmpApi for IcmpSocketApi {
    fn new() -> Result<Self, crate::ping::Error> {
        initialize_winsock()?;
        Ok(IcmpSocketApi {
            socket4: None,
            socket6: None,
            ttl: None,
        })
    }

    fn set_ttl(&mut self, ttl: u8) -> Result<(), crate::ping::Error> {
        if let Some(socket4) = &mut self.socket4 {
            let ttl = ttl as u32;
            socket4.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_TTL, &ttl)?;
            socket4.setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_MULTICAST_TTL, &ttl)?;
        }
        if let Some(socket6) = &mut self.socket6 {
            let ttl = ttl as u32;
            socket6.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_UNICAST_HOPS, &ttl)?;
            socket6.setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_MULTICAST_HOPS, &ttl)?;
        }
        self.ttl = Some(ttl);
        Ok(())
    }

    fn send(&mut self, target: std::net::IpAddr, length: usize, sequence: u16, timestamp: u64) -> Result<(), crate::ping::Error> {
        match target {
            IpAddr::V4(_) => self.get_socket4()?.send(target, length, sequence, timestamp),
            IpAddr::V6(_) => self.get_socket6()?.send(target, length, sequence, timestamp),
        }
    }

    fn recv(&mut self, timeout: std::time::Duration) -> Result<IcmpResult, crate::ping::Error> {
        if let Some(socket4) = &mut self.socket4 {
            if let Some(answer) = socket4.recv()? {
                return Ok(answer);
            }
        }

        if let Some(socket6) = &mut self.socket6 {
            if let Some(answer) = socket6.recv()? {
                return Ok(answer);
            }
        }

        let timeout = timeout.as_millis() as u32;

        let events = match (self.socket4.is_some(), self.socket6.is_some()) {
            (true, true) => vec![
                self.socket4.as_ref().unwrap().overlapped.hEvent,
                self.socket6.as_ref().unwrap().overlapped.hEvent,
            ],
            (true, false) => vec![self.socket4.as_ref().unwrap().overlapped.hEvent],
            (false, true) => vec![self.socket6.as_ref().unwrap().overlapped.hEvent],
            (false, false) => unreachable!(),
        };

        // Wait for overlapped operation to complete
        let rc = unsafe { WinSock::WSAWaitForMultipleEvents(events.as_slice(), false, timeout, true) };

        match rc.0 {
            WinSock::WSA_WAIT_TIMEOUT => Ok(IcmpResult::Timeout),
            WinSock::WSA_WAIT_FAILED => Err(std::io::Error::from_raw_os_error(unsafe { WinSock::WSAGetLastError() }.0 as i32))?,
            n => {
                let index = n - WinSock::WSA_WAIT_EVENT_0.0 as u32;
                let event_handle = events[index as usize];

                if let Some(socket4) = &mut self.socket4 {
                    if socket4.overlapped.hEvent == event_handle {
                        return socket4.get_overlapped_result();
                    }
                }
                if let Some(socket6) = &mut self.socket6 {
                    if socket6.overlapped.hEvent == event_handle {
                        return socket6.get_overlapped_result();
                    }
                }
                unreachable!("Received event for unknown socket");
            }
        }
    }
}

fn initialize_winsock() -> Result<(), crate::ping::Error> {
    let mut wsadata = WinSock::WSADATA::default();
    const VERSION_REQUESTED: u16 = 0x0202;
    let result = unsafe { WinSock::WSAStartup(VERSION_REQUESTED, &mut wsadata) };
    if result != 0 {
        Err(std::io::Error::from_raw_os_error(result))?
    } else {
        Ok(())
    }
}

impl IcmpSocketApi {
    fn get_socket4(&mut self) -> Result<&mut IcmpSocket, crate::ping::Error> {
        if self.socket4.is_none() {
            self.socket4 = Some(IcmpSocket::new_ipv4()?);
            if let Some(ttl) = self.ttl {
                self.socket4
                    .as_mut()
                    .unwrap()
                    .setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_TTL, &ttl)?;
                self.socket4
                    .as_mut()
                    .unwrap()
                    .setsockopt(WinSock::IPPROTO_IP.0, WinSock::IP_MULTICAST_TTL, &ttl)?;
            }
        }
        Ok(self.socket4.as_mut().unwrap())
    }

    fn get_socket6(&mut self) -> Result<&mut IcmpSocket, crate::ping::Error> {
        if self.socket6.is_none() {
            self.socket6 = Some(IcmpSocket::new_ipv6()?);
            let enabled: u32 = 1;
            self.socket6
                .as_mut()
                .unwrap()
                .setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_HOPLIMIT, &enabled)?;
            if let Some(ttl) = self.ttl {
                self.socket6
                    .as_mut()
                    .unwrap()
                    .setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_UNICAST_HOPS, &ttl)?;
                self.socket6
                    .as_mut()
                    .unwrap()
                    .setsockopt(WinSock::IPPROTO_IPV6.0, WinSock::IPV6_MULTICAST_HOPS, &ttl)?;
            }
        }
        Ok(self.socket6.as_mut().unwrap())
    }
}

fn get_wsarecvmsg(socket: WinSock::SOCKET) -> Result<WinSock::LPFN_WSARECVMSG, crate::ping::Error> {
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

    if result == WinSock::SOCKET_ERROR {
        let err = unsafe { WinSock::WSAGetLastError() };
        if err == WinSock::WSAEOPNOTSUPP {
            return Ok(None);
        } else {
            Err(std::io::Error::from_raw_os_error(err.0 as i32))?;
        }
    }

    assert_eq!(bytes_returned, std::mem::size_of::<*const c_void>() as u32);

    Ok(unsafe { std::mem::transmute::<*const std::ffi::c_void, WinSock::LPFN_WSARECVMSG>(recvmsg_function_pointer) })
}
