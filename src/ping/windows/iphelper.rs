use super::FromIpv4Addr;
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
use windows::Win32::{
    Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, NO_ERROR, WAIT_EVENT, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Globalization::lstrlenW,
    NetworkManagement::IpHelper::{self, GetIpErrorString, ICMP_ECHO_REPLY32, IP_REQ_TIMED_OUT},
    Networking::WinSock,
};

use crate::ping::{sockaddr::SockAddr, IcmpMessage};

type Error = crate::ping::Error;

struct IpHelperHandle {
    icmp_handle: HANDLE,
    // target: std::net::SocketAddr,
    event_handles: Vec<HANDLE>,
    packets: Vec<PacketInfo>,
    ttl: u8,
    send_buffer: Vec<u8>,
}

pub struct IpHelperApi {
    handle4: Option<IpHelperHandle>,
    handle6: Option<IpHelperHandle>,
    ttl: u8,
}

struct PacketInfo {
    /// Sequence number from request. IpHelper API doesn't support specifying
    /// sequence number, so we need to store it.
    sequence: u16,
    /// Buffer for reply data.
    reply_buffer: Vec<u8>,
    /// Timestamp from request.
    timestamp: std::time::SystemTime,
    /// Target IP
    target: std::net::IpAddr,
}

struct Ipv6AddressEx(IpHelper::IPV6_ADDRESS_EX);

fn format_iphelper_error(error: u32) -> Result<String, std::io::Error> {
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    let pwstr = windows::core::PWSTR::from_raw(buffer.as_mut_ptr());
    let result = unsafe { GetIpErrorString(error, pwstr, &mut size) };
    if result == NO_ERROR.0 {
        let length = unsafe { lstrlenW(pwstr) };
        Ok(String::from_utf16_lossy(&buffer[..length as usize]).trim_end().to_string())
    } else {
        Err(std::io::Error::from_raw_os_error(result as i32))
    }
}

/// Get the last error from IPHelper API and return it as an `std::io::Error`.
/// The documentation for IcmpParseReplies says that when it returns 0, call
/// GetLastError to get the error code, but the error codes returned are
/// actually IPHelper error codes, not Win32 error codes.
/// https://docs.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpparsereplies
fn get_last_iphelper_error() -> Result<std::io::Error, std::io::Error> {
    let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
    error_from_iphelper_error(last_error.0)
}

fn error_from_iphelper_error(error: u32) -> Result<std::io::Error, std::io::Error> {
    let formatted_error = format_iphelper_error(error)?;
    match error {
        IP_REQ_TIMED_OUT => Ok(std::io::Error::new(std::io::ErrorKind::TimedOut, formatted_error)),
        _ => Ok(std::io::Error::new(std::io::ErrorKind::Other, formatted_error)),
    }
}

impl From<Ipv6AddressEx> for SocketAddrV6 {
    fn from(addr: Ipv6AddressEx) -> Self {
        let words = addr.0.sin6_addr;
        let port = u16::from_be(addr.0.sin6_port);
        let flowinfo = addr.0.sin6_flowinfo;
        let scope_id = addr.0.sin6_scope_id;
        SocketAddrV6::new(
            Ipv6Addr::new(
                u16::from_be(words[0]),
                u16::from_be(words[1]),
                u16::from_be(words[2]),
                u16::from_be(words[3]),
                u16::from_be(words[4]),
                u16::from_be(words[5]),
                u16::from_be(words[6]),
                u16::from_be(words[7]),
            ),
            port,
            flowinfo,
            scope_id,
        )
    }
}

impl IpHelperHandle {
    fn set_ttl(&mut self, ttl: u8) -> Result<(), std::io::Error> {
        self.ttl = ttl;
        Ok(())
    }

    fn send(&mut self, target: std::net::IpAddr, length: usize, sequence: u16) -> Result<std::time::SystemTime, Error> {
        let event_handle = unsafe { windows::Win32::System::Threading::CreateEventW(None, true, false, None) }?;

        let ip_options = IpHelper::IP_OPTION_INFORMATION32 {
            Ttl: self.ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: std::ptr::null_mut(),
        };

        let (send_result, packet_info) = match target {
            std::net::IpAddr::V4(addr) => {
                let sourceaddress: u32 = 0;
                let destinationaddress = WinSock::IN_ADDR::from_ipv4addr(&addr);
                let destinationaddress = unsafe { destinationaddress.S_un.S_addr };

                self.send_buffer.resize(length, 0);
                let timestamp = std::time::SystemTime::now();
                super::super::construct_icmp_payload(self.send_buffer.as_mut(), timestamp);

                let mut packet_info = PacketInfo {
                    sequence,
                    reply_buffer: vec![0; 2048],
                    timestamp,
                    target,
                };

                (
                    unsafe {
                        // zero the reply_buffer
                        packet_info.reply_buffer.iter_mut().for_each(|x| *x = 0);
                        IpHelper::IcmpSendEcho2Ex(
                            self.icmp_handle,
                            event_handle,
                            None,
                            None,
                            sourceaddress,
                            destinationaddress,
                            self.send_buffer.as_ptr() as *const _,
                            self.send_buffer.len() as u16,
                            Some(&ip_options as *const _ as *const _),
                            packet_info.reply_buffer.as_mut_ptr() as *mut _,
                            packet_info.reply_buffer.len() as u32,
                            2500,
                        )
                    },
                    packet_info,
                )
            }
            std::net::IpAddr::V6(ipv6addr) => unsafe {
                let sourceaddress = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
                let sourceaddress: SockAddr = sourceaddress.into();

                // let sourceaddress = null_mut();
                let sockaddr = SockAddr::from(SocketAddrV6::new(ipv6addr, 0, 0, 0));
                let destinationaddress = &sockaddr.sin6 as *const _;

                self.send_buffer.resize(length, 0);
                let timestamp = std::time::SystemTime::now();
                super::super::construct_icmp_payload(self.send_buffer.as_mut(), timestamp);

                let mut packet_info = PacketInfo {
                    sequence,
                    reply_buffer: vec![0; 2048],
                    timestamp,
                    target,
                };

                (
                    IpHelper::Icmp6SendEcho2(
                        self.icmp_handle,
                        event_handle,
                        None,
                        None,
                        &sourceaddress.sin6,
                        destinationaddress,
                        self.send_buffer.as_ptr() as *const _,
                        self.send_buffer.len() as u16,
                        Some(&ip_options as *const _ as *const _),
                        packet_info.reply_buffer.as_mut_ptr() as *mut _,
                        packet_info.reply_buffer.len() as u32,
                        2500,
                    ),
                    packet_info,
                )
            },
        };

        if send_result == 0 {
            let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
            if last_error == ERROR_IO_PENDING {
                let ts = packet_info.timestamp;
                self.event_handles.push(event_handle);
                self.packets.push(packet_info);
                Ok(ts)
            } else {
                unsafe { CloseHandle(event_handle) }?;
                Err(std::io::Error::last_os_error())?
            }
        } else {
            unimplemented!("IcmpSendEcho2Ex returned {}", send_result); // should never complete immediately
        }
    }

    fn complete_recv(&mut self, index: usize, rx_timestamp: std::time::SystemTime) -> Result<crate::ping::IcmpResult, Error> {
        let event_handle = self.event_handles.remove(index);
        unsafe { CloseHandle(event_handle)? };

        let mut packet_info = self.packets.remove(index);

        match packet_info.target {
            std::net::IpAddr::V4(_) => {
                match unsafe {
                    IpHelper::IcmpParseReplies(
                        packet_info.reply_buffer.as_mut_ptr() as *mut _,
                        packet_info.reply_buffer.len() as u32,
                    )
                } {
                    0 => {
                        let error = get_last_iphelper_error()?;
                        match error.kind() {
                            std::io::ErrorKind::TimedOut => Ok(crate::ping::IcmpResult::Timeout),
                            _ => Err(error)?,
                        }
                    }
                    1 => {
                        // ICMP_ECHO_REPLY32 contains the round-trip-time
                        // measured by the operating system, but it only has a
                        // resolution of milliseconds, so we don't provide it to
                        // the user.
                        let echo_reply: &ICMP_ECHO_REPLY32 = &unsafe { *(packet_info.reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY32) };

                        let _packet = unsafe { std::slice::from_raw_parts(echo_reply.Data as *const u8, echo_reply.DataSize as usize) };
                        if echo_reply.Status == IpHelper::IP_SUCCESS {
                            Ok(crate::ping::IcmpResult::EchoReply(crate::ping::EchoReply {
                                addr: std::net::SocketAddr::V4(SocketAddrV4::new(u32::from_be(echo_reply.Address).into(), 0)),
                                message: icmp_message_from_icmp_echo_reply32(echo_reply, &packet_info),
                                timestamp: rx_timestamp,
                                socket_timestamp: None, // Available in ICMP_ECHO_REPLY32, but precision is too low
                                recvttl: Some(echo_reply.Options.Ttl as u32),
                            }))
                        } else {
                            let (icmp_type, icmp_code) = map_status(echo_reply.Status);
                            Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                                error: None,
                                addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(echo_reply.Address.into(), 0))),
                                original_message: None, // FIXME
                                offender: Some(std::net::SocketAddr::V4(SocketAddrV4::new(echo_reply.Address.into(), 0))),
                                icmp_type,          // FIXME
                                icmp_code,          // FIXME
                                time: rx_timestamp, // FIXME
                            }))
                        }
                    }
                    _ => unreachable!(),
                }
            }
            std::net::IpAddr::V6(_) => {
                let parse_result = unsafe {
                    IpHelper::Icmp6ParseReplies(
                        packet_info.reply_buffer.as_mut_ptr() as *mut _,
                        packet_info.reply_buffer.len() as u32,
                    )
                };
                match parse_result {
                    0 => {
                        let error = get_last_iphelper_error()?;
                        match error.kind() {
                            std::io::ErrorKind::TimedOut => Ok(crate::ping::IcmpResult::Timeout),
                            _ => Err(error)?,
                        }
                    }
                    1 => {
                        let echo_reply: &IpHelper::ICMPV6_ECHO_REPLY_LH =
                            &unsafe { *(packet_info.reply_buffer.as_ptr() as *const IpHelper::ICMPV6_ECHO_REPLY_LH) };

                        match echo_reply.Status {
                            IpHelper::IP_SUCCESS => Ok(crate::ping::IcmpResult::EchoReply(crate::ping::EchoReply {
                                addr: std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address))),
                                message: crate::ping::IcmpMessage {
                                    icmp_type: crate::ping::IcmpType::EchoReply(0),
                                    id: 0,
                                    seq: packet_info.sequence,
                                    timestamp: Some(packet_info.timestamp),
                                },
                                timestamp: rx_timestamp,
                                socket_timestamp: None, // Unavailable
                                recvttl: None,          // Unavailable
                            })),
                            _ => {
                                let (icmp_type, icmp_code) = map_status(echo_reply.Status);
                                Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                                    error: None,
                                    addr: Some(std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address)))),
                                    original_message: None, // FIXME
                                    offender: Some(std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address)))),
                                    icmp_type,          // FIXME
                                    icmp_code,          // FIXME
                                    time: rx_timestamp, // FIXME
                                }))
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}

fn map_status(status: u32) -> (Option<u8>, Option<u8>) {
    match status {
        IpHelper::IP_SUCCESS => (None, None),
        IpHelper::IP_BUF_TOO_SMALL => unreachable!("IP_BUF_TOO_SMALL"),
        IpHelper::IP_DEST_NET_UNREACHABLE => (Some(3), Some(0)),
        IpHelper::IP_DEST_HOST_UNREACHABLE => (Some(3), Some(1)),
        IpHelper::IP_DEST_PROT_UNREACHABLE => (Some(3), Some(2)),
        IpHelper::IP_DEST_PORT_UNREACHABLE => (Some(3), Some(3)),
        IpHelper::IP_NO_RESOURCES => unreachable!("IP_NO_RESOURCES"),
        IpHelper::IP_BAD_OPTION => unreachable!("IP_BAD_OPTION"),
        IpHelper::IP_HW_ERROR => unreachable!("IP_HW_ERROR"),
        IpHelper::IP_PACKET_TOO_BIG => unreachable!("IP_PACKET_TOO_BIG"),
        IpHelper::IP_REQ_TIMED_OUT => unreachable!("IP_REQ_TIMED_OUT"),
        IpHelper::IP_BAD_REQ => unreachable!("IP_BAD_REQ"),
        IpHelper::IP_BAD_ROUTE => unreachable!("IP_BAD_ROUTE"),
        IpHelper::IP_TTL_EXPIRED_TRANSIT => (Some(11), Some(0)),
        IpHelper::IP_TTL_EXPIRED_REASSEM => (Some(11), Some(1)),
        IpHelper::IP_PARAM_PROBLEM => unreachable!("IP_PARAM_PROBLEM"),
        IpHelper::IP_SOURCE_QUENCH => unreachable!("IP_SOURCE_QUENCH"),
        IpHelper::IP_OPTION_TOO_BIG => unreachable!("IP_OPTION_TOO_BIG"),
        IpHelper::IP_BAD_DESTINATION => unreachable!("IP_BAD_DESTINATION"),
        IpHelper::IP_GENERAL_FAILURE => unreachable!("IP_ADDR_DELETED"),
        _ => unreachable!("unknown status: {}", status),
    }
}

fn icmp_message_from_icmp_echo_reply32(echo_reply: &ICMP_ECHO_REPLY32, packet_info: &PacketInfo) -> IcmpMessage {
    let data = unsafe { std::slice::from_raw_parts(echo_reply.Data as *const u8, echo_reply.DataSize as usize) };
    let _options =
        unsafe { std::slice::from_raw_parts(echo_reply.Options.OptionsData as *const u8, echo_reply.Options.OptionsSize as usize) };
    IcmpMessage {
        icmp_type: match echo_reply.Status {
            IpHelper::IP_SUCCESS => crate::ping::IcmpType::EchoReply(u64::from_be_bytes(data[0..8].try_into().unwrap())),
            IpHelper::IP_DEST_NET_UNREACHABLE => {
                crate::ping::IcmpType::IPv4DestinationUnreachable(Ok(crate::ping::IPv4DestinationUnreachable::NetUnreachable))
            }
            IpHelper::IP_HOP_LIMIT_EXCEEDED => crate::ping::IcmpType::TimeExceeded,
            _ => todo!(),
        },
        id: 0,
        seq: packet_info.sequence,
        timestamp: crate::ping::timestamp_from_payload(data),
    }
}

impl crate::ping::IcmpApi for IpHelperApi {
    fn new() -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(IpHelperApi {
            handle4: None,
            handle6: None,
            ttl: 64,
        })
    }

    fn set_ttl(&mut self, ttl: u8) -> Result<(), Error> {
        if let Some(handle4) = &mut self.handle4 {
            handle4.set_ttl(ttl)?;
        }
        if let Some(handle6) = &mut self.handle6 {
            handle6.set_ttl(ttl)?;
        }
        self.ttl = ttl;
        Ok(())
    }

    fn send(&mut self, target: std::net::IpAddr, length: usize, sequence: u16) -> Result<std::time::SystemTime, Error> {
        match target {
            std::net::IpAddr::V4(_) => self.ipv4_handle()?.send(target, length, sequence),
            std::net::IpAddr::V6(_) => self.ipv6_handle()?.send(target, length, sequence),
        }
    }

    fn recv(&mut self, timeout: std::time::Duration) -> Result<crate::ping::IcmpResult, Error> {
        let ipv4_handle_count = self.handle4.as_ref().map(|handle| handle.event_handles.len()).unwrap_or(0);
        let all_event_handles = self
            .handle4
            .as_ref()
            .map(|handle| handle.event_handles.as_slice())
            .unwrap_or(&[])
            .iter()
            .chain(
                self.handle6
                    .as_ref()
                    .map(|handle| handle.event_handles.as_slice())
                    .unwrap_or(&[])
                    .iter(),
            )
            .copied()
            .collect::<Vec<_>>();

        if all_event_handles.is_empty() {
            std::thread::sleep(timeout);
            return Ok(crate::ping::IcmpResult::Timeout);
        }

        let wait_result = unsafe {
            let handles = &all_event_handles[..all_event_handles.len().min(64)];
            windows::Win32::System::Threading::WaitForMultipleObjects(handles, false, timeout.as_millis() as u32)
        };

        let rx_timestamp = std::time::SystemTime::now();

        match wait_result {
            WAIT_TIMEOUT => Ok(crate::ping::IcmpResult::Timeout),
            WAIT_FAILED => Err(std::io::Error::last_os_error())?,
            WAIT_EVENT(n) => {
                let index = (n - WAIT_OBJECT_0.0) as usize;

                if index < ipv4_handle_count {
                    self.handle4.as_mut().unwrap().complete_recv(index, rx_timestamp)
                } else {
                    self.handle6
                        .as_mut()
                        .unwrap()
                        .complete_recv(index - ipv4_handle_count, rx_timestamp)
                }
            }
        }
    }
}

impl IpHelperApi {
    fn ipv4_handle(&mut self) -> Result<&mut IpHelperHandle, std::io::Error> {
        if self.handle4.is_none() {
            let icmp_handle = unsafe { IpHelper::IcmpCreateFile() }?;
            self.handle4 = Some(IpHelperHandle {
                icmp_handle,
                event_handles: Vec::new(),
                packets: Vec::new(),
                ttl: self.ttl,
                send_buffer: Vec::new(),
            });
        }
        Ok(self.handle4.as_mut().unwrap())
    }

    fn ipv6_handle(&mut self) -> Result<&mut IpHelperHandle, std::io::Error> {
        if self.handle6.is_none() {
            let icmp_handle = unsafe { IpHelper::Icmp6CreateFile() }?;
            self.handle6 = Some(IpHelperHandle {
                icmp_handle,
                event_handles: Vec::new(),
                packets: Vec::new(),
                ttl: self.ttl,
                send_buffer: Vec::new(),
            });
        }
        Ok(self.handle6.as_mut().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_address_conversion() {
        let addr = Ipv6AddressEx(IpHelper::IPV6_ADDRESS_EX {
            sin6_addr: [
                0x2001u16.to_be(),
                0x0db8u16.to_be(),
                0x85a3u16.to_be(),
                0x0000u16.to_be(),
                0x0000u16.to_be(),
                0x8a2eu16.to_be(),
                0x0370u16.to_be(),
                0x7334u16.to_be(),
            ],
            sin6_port: 0x1234u16.to_be(),
            sin6_flowinfo: 0x5678,
            sin6_scope_id: 0x9abc,
        });
        let socket_addr: SocketAddrV6 = addr.into();
        assert_eq!(
            socket_addr,
            SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334),
                0x1234,
                0x5678,
                0x9abc
            )
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_ip_helper_error() {
        let error = error_from_iphelper_error(IpHelper::IP_REQ_TIMED_OUT).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "Request timed out.");

        let error = error_from_iphelper_error(IpHelper::IP_BAD_REQ).unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.to_string(), "Bad request.");
    }
}
