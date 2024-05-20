use super::FromIpv4Addr;
use std::net::{Ipv6Addr, SocketAddrV4, SocketAddrV6};
use windows::Win32::{
    Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE, WAIT_EVENT, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    NetworkManagement::IpHelper::{self, ICMP_ECHO_REPLY32},
    Networking::WinSock,
};

use crate::ping::{sockaddr::SockAddr, IcmpMessage};

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
    seq: u16,
    /// Buffer for reply data.
    reply_buffer: Vec<u8>,
    /// Timestamp from request.
    timestamp: u64,
    /// Target IP
    target: std::net::IpAddr,
}

struct Ipv6AddressEx(IpHelper::IPV6_ADDRESS_EX);

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

    fn send(&mut self, target: std::net::IpAddr, length: usize, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
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
                super::super::construct_icmp_payload(self.send_buffer.as_mut(), timestamp);

                let mut packet_info = PacketInfo {
                    seq: sequence,
                    reply_buffer: vec![0; 2048],
                    timestamp,
                    target,
                };

                (
                    unsafe {
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
                            5000,
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
                super::super::construct_icmp_payload(self.send_buffer.as_mut(), timestamp);

                let mut packet_info = PacketInfo {
                    seq: sequence,
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
                        5000,
                    ),
                    packet_info,
                )
            },
        };

        if send_result == 0 {
            let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
            if last_error == ERROR_IO_PENDING {
                self.event_handles.push(event_handle);
                self.packets.push(packet_info);
                Ok(())
            } else {
                unsafe { CloseHandle(event_handle) }?;
                Err(std::io::Error::last_os_error())
            }
        } else {
            unimplemented!("IcmpSendEcho2Ex returned {}", send_result); // should never complete immediately
        }
    }

    fn complete_recv(&mut self, index: usize) -> Result<crate::ping::IcmpResult, std::io::Error> {
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
                    0 => Err(std::io::Error::last_os_error()),
                    1 => {
                        let echo_reply: &ICMP_ECHO_REPLY32 = &unsafe { *(packet_info.reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY32) };
                        let _packet = unsafe { std::slice::from_raw_parts(echo_reply.Data as *const u8, echo_reply.DataSize as usize) };
                        if echo_reply.Status == IpHelper::IP_SUCCESS {
                            Ok(crate::ping::IcmpResult::IcmpPacket(crate::ping::IcmpPacket {
                                addr: std::net::SocketAddr::V4(SocketAddrV4::new(u32::from_be(echo_reply.Address).into(), 0)),
                                message: icmp_messager_from_icmp_echo_reply32(echo_reply, &packet_info),
                                time: std::time::Instant::now(),
                                recvttl: Some(echo_reply.Options.Ttl as u32),
                            }))
                        } else {
                            let (icmp_type, icmp_code) = map_status(echo_reply.Status);
                            Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                                error: None,
                                addr: Some(std::net::SocketAddr::V4(SocketAddrV4::new(echo_reply.Address.into(), 0))),
                                original_message: None, // FIXME
                                offender: Some(std::net::SocketAddr::V4(SocketAddrV4::new(echo_reply.Address.into(), 0))),
                                icmp_type,                       // FIXME
                                icmp_code,                       // FIXME
                                time: std::time::Instant::now(), // FIXME
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
                    0 => Err(std::io::Error::last_os_error()),
                    1 => {
                        let echo_reply: &IpHelper::ICMPV6_ECHO_REPLY_LH =
                            &unsafe { *(packet_info.reply_buffer.as_ptr() as *const IpHelper::ICMPV6_ECHO_REPLY_LH) };

                        match echo_reply.Status {
                            IpHelper::IP_SUCCESS => Ok(crate::ping::IcmpResult::IcmpPacket(crate::ping::IcmpPacket {
                                addr: std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address))),
                                message: crate::ping::IcmpMessage {
                                    icmp_type: crate::ping::IcmpType::EchoReply(packet_info.timestamp),
                                    id: 0,
                                    seq: packet_info.seq,
                                    timestamp: Some(packet_info.timestamp),
                                },
                                time: std::time::Instant::now(),
                                recvttl: None, // Unavailable
                            })),
                            _ => {
                                let (icmp_type, icmp_code) = map_status(echo_reply.Status);
                                println!(
                                    "{:?}",
                                    Some(std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address))))
                                );
                                Ok(crate::ping::IcmpResult::RecvError(crate::ping::RecvError {
                                    error: None,
                                    addr: Some(std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address)))),
                                    original_message: None, // FIXME
                                    offender: Some(std::net::SocketAddr::V6(SocketAddrV6::from(Ipv6AddressEx(echo_reply.Address)))),
                                    icmp_type,                       // FIXME
                                    icmp_code,                       // FIXME
                                    time: std::time::Instant::now(), // FIXME
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

fn icmp_messager_from_icmp_echo_reply32(echo_reply: &ICMP_ECHO_REPLY32, packet_info: &PacketInfo) -> IcmpMessage {
    let data = unsafe { std::slice::from_raw_parts(echo_reply.Data as *const u8, echo_reply.DataSize as usize) };
    let _options =
        unsafe { std::slice::from_raw_parts(echo_reply.Options.OptionsData as *const u8, echo_reply.Options.OptionsSize as usize) };
    // println!("options: {:?}", options);
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
        seq: packet_info.seq,
        timestamp: Some(u64::from_be_bytes(data[0..8].try_into().unwrap())),
    }
}

impl crate::ping::IcmpApi for IpHelperApi {
    fn new() -> Result<Self, std::io::Error>
    where
        Self: Sized,
    {
        Ok(IpHelperApi {
            handle4: None,
            handle6: None,
            ttl: 64,
        })
    }

    fn set_ttl(&mut self, ttl: u8) -> Result<(), std::io::Error> {
        if let Some(handle4) = &mut self.handle4 {
            handle4.set_ttl(ttl)?;
        }
        if let Some(handle6) = &mut self.handle6 {
            handle6.set_ttl(ttl)?;
        }
        self.ttl = ttl;
        Ok(())
    }

    fn send(&mut self, target: std::net::IpAddr, length: usize, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        match target {
            std::net::IpAddr::V4(_) => self.ipv4_handle()?.send(target, length, sequence, timestamp),
            std::net::IpAddr::V6(_) => self.ipv6_handle()?.send(target, length, sequence, timestamp),
        }
    }

    fn recv(&mut self, timeout: std::time::Duration) -> Result<crate::ping::IcmpResult, std::io::Error> {
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
            windows::Win32::System::Threading::WaitForMultipleObjects(all_event_handles.as_slice(), false, timeout.as_millis() as u32)
        };

        match wait_result {
            WAIT_TIMEOUT => Ok(crate::ping::IcmpResult::Timeout),
            WAIT_FAILED => Err(std::io::Error::last_os_error()),
            WAIT_EVENT(n) => {
                let index = (n - WAIT_OBJECT_0.0) as usize;
                if index < ipv4_handle_count {
                    self.handle4.as_mut().unwrap().complete_recv(index)
                } else {
                    self.handle6.as_mut().unwrap().complete_recv(index - ipv4_handle_count)
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
}
