use std::{
    ffi::c_void,
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

use windows::{
    core::{PSTR, PWSTR},
    Win32::{
        Foundation::{HANDLE, HLOCAL},
        Networking::WinSock::{self, WSACloseEvent, WSAGetLastError, SOCKET_ERROR},
        System::{
            Diagnostics::Debug::{self, FormatMessageW},
            IO::{CancelIoEx, OVERLAPPED},
        },
    },
};

pub struct PingProtocol {
    socket: WinSock::SOCKET,
    // send_to_overlapped: Vec<OVERLAPPED>,
    overlapped_recvfrom: OVERLAPPED,
    overlapped_addr: super::sockaddr::SockAddr,
    recv_buffer: [u8; 1500],
    target: SocketAddr,
}

impl Drop for PingProtocol {
    fn drop(&mut self) {
        if self.overlapped_recvfrom.hEvent != HANDLE::default() {
            unsafe {
                let handle = HANDLE(self.socket.0 as isize);
                println!("Cancelling");
                CancelIoEx(handle, Some(&self.overlapped_recvfrom)).unwrap();
            }
        }
        unsafe {
            println!("Closing socket");
            let close_result = WinSock::closesocket(self.socket);
            assert!(close_result == 0);
        }
    }
}

impl PingProtocol {
    pub fn new(target: SocketAddr) -> Result<Self, String> {
        unsafe {
            let mut wsadata = WinSock::WSADATA::default();
            WinSock::WSAStartup(0x0202, &mut wsadata);

            // let icmp = WinSock::getprotobyname(s!("icmp"));
            // let icmp_proto = (*icmp).p_proto;

            let family = match target {
                SocketAddr::V4(_) => WinSock::AF_INET,
                SocketAddr::V6(_) => WinSock::AF_INET6,
            };

            let proto = match target {
                SocketAddr::V4(_) => WinSock::IPPROTO_ICMP,
                SocketAddr::V6(_) => WinSock::IPPROTO_ICMPV6,
            };

            let socket = WinSock::WSASocketW(
                family.0 as i32,
                WinSock::SOCK_RAW.0,
                proto.0,
                None,
                0,
                WinSock::WSA_FLAG_OVERLAPPED,
            );

            assert!(socket != WinSock::INVALID_SOCKET);

            // let last_error = WinSock::WSAGetLastError();
            // println!("{:?}", last_error);

            // println!("{:?}", socket);
            let winping = PingProtocol {
                socket,
                // send_to_overlapped: vec![],
                overlapped_recvfrom: Default::default(),
                recv_buffer: [0u8; 1500],
                target,
                overlapped_addr: Default::default(),
            };

            Ok(winping)
        }
    }

    pub fn send(&mut self, sequence: u16, timestamp: u64) -> Result<(), std::io::Error> {
        unsafe {
            let mut packet16 = [0u16; 16];
            let packet: &mut [u8; 32] = std::mem::transmute(&mut packet16);
            let identifier = sequence;
            let code = match self.target {
                SocketAddr::V4(_) => 8,
                SocketAddr::V6(_) => 128,
            };
            packet[0] = code; // echo request
            packet[1] = 0;
            packet[2] = 0; // checksum msb
            packet[3] = 0; // checksum lsb
            packet[4..6].copy_from_slice(&identifier.to_be_bytes());
            packet[6..8].copy_from_slice(&sequence.to_be_bytes());

            // Insert timestamp
            packet[8..16].copy_from_slice(&timestamp.to_be_bytes());

            // Create PSTR/WSABUF for icmp packet
            let packet_pstr = PSTR::from_raw(packet.as_mut_ptr());
            let packet_wsabuf = [WinSock::WSABUF {
                len: 32,
                buf: packet_pstr,
            }];

            // Calculate checksum
            let data = packet16.as_mut_ptr();
            // println!("data = {:?}", data);
            let words = (packet.len() / 2) as isize;
            let mut checksum: u32 = 0;
            for pos in 0..words {
                let word = *data.offset(pos);
                checksum += word as u32;
            }
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
            *data.offset(1) = (checksum as u16) ^ 0xFFFF;

            // println!("packet = {:?}", packet);

            let mut bytes_sent: u32 = 0;

            let target_sa: super::sockaddr::SockAddr = self.target.into();

            // println!("{:?}", target_sa.sin6.sin6_addr.u.Word);

            let result = WinSock::WSASendTo(
                self.socket,
                &packet_wsabuf,
                Some(&mut bytes_sent),
                0,
                Some(target_sa.as_ref()),
                std::mem::size_of::<super::sockaddr::SockAddr>() as i32,
                None,
                None,
            );
            match result {
                0 => (),
                WinSock::SOCKET_ERROR => {
                    let err = WSAGetLastError();
                    eprintln!("{:?}", err);
                    eprintln!("{:?}", lookup_error(err.0 as u32).unwrap());

                    panic!();
                }
                _ => panic!(),
            }
            assert!(result == 0);
            Ok(())
        }
    }

    pub fn recv(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<super::PingResponse>, Box<dyn std::error::Error>> {
        unsafe {
            let recv_wsabuf = [WinSock::WSABUF {
                len: self.recv_buffer.len() as u32,
                buf: PSTR::from_raw(self.recv_buffer.as_mut_ptr()),
            }];
            let mut bytes_received = 0u32;

            //let mut recv_sockaddr: super::sockaddr::SockAddr = std::mem::zeroed();
            let mut recv_fromlen = std::mem::size_of::<crate::ping::sockaddr::SockAddr>() as i32;

            // let mut recv_sockaddr = WinSock::SOCKADDR::default();
            // let mut recv_fromlen = std::mem::size_of::<WinSock::SOCKADDR>() as i32;

            let mut flags = 0u32;

            if self.overlapped_recvfrom.hEvent == HANDLE::default() {
                // create a new overlapped operation
                self.overlapped_recvfrom.hEvent = WinSock::WSACreateEvent().unwrap();
                // start receive operation
                // println!("recvfrom...");
                // println!("self.socket = {:?}", self.socket);
                // println!("recv_wsabuf = {:?}", recv_wsabuf);
                let result = WinSock::WSARecvFrom(
                    self.socket,
                    &recv_wsabuf,
                    Some(&mut bytes_received as *mut u32),
                    &mut flags as *mut u32,
                    Some(self.overlapped_addr.as_mut()),
                    Some(&mut recv_fromlen),
                    Some(&mut self.overlapped_recvfrom as *mut OVERLAPPED),
                    None,
                );

                match result {
                    0 => {
                        // The operation completed without overlap.
                        WinSock::WSACloseEvent(self.overlapped_recvfrom.hEvent).unwrap();
                        self.overlapped_recvfrom.hEvent = HANDLE::default();
                        return Ok(self.complete_recv_from(
                            self.overlapped_addr.clone().try_into()?,
                            bytes_received as usize,
                        ));
                    }
                    SOCKET_ERROR => {
                        // The operation failed (or overlapped operation is pending)
                        let err = WinSock::WSAGetLastError();
                        // println!("err = {:?}", err);
                        assert!(err == WinSock::WSA_IO_PENDING);
                    }
                    _ => {
                        abort();
                    }
                }
            }

            let timeout = timeout.as_millis() as u32;

            // An overlapped operation has now been started
            let rc = WinSock::WSAWaitForMultipleEvents(
                &[self.overlapped_recvfrom.hEvent],
                true,
                timeout,
                true,
            );
            // println!("rc = {:?}", rc);
            if rc.0 == WinSock::WSA_WAIT_TIMEOUT {
                return Ok(None);
            }
            // println!("wfm: {:?}", rc);
            assert!(rc.0 != WinSock::WSA_WAIT_FAILED);
            let mut flags = 0u32;
            WinSock::WSAGetOverlappedResult(
                self.socket,
                &self.overlapped_recvfrom,
                &mut bytes_received as *mut u32,
                false,
                &mut flags as *mut u32,
            )
            .unwrap();

            WSACloseEvent(self.overlapped_recvfrom.hEvent).unwrap();
            self.overlapped_recvfrom.hEvent = HANDLE::default();
            // println!("bytes_received = {:?}", bytes_received);
            // println!("{:?}", self.overlapped_addr.as_ref().sa_family);
            let sa: Result<SocketAddr, String> = self.overlapped_addr.clone().try_into();
            // println!("recv_sockaddr = {:?}", sa);
            Ok(self.complete_recv_from(sa.unwrap(), bytes_received as usize))
        }
    }

    fn complete_recv_from(
        &self,
        addr: SocketAddr,
        recv_fromlen: usize,
    ) -> Option<super::PingResponse> {
        // println!("getresultresult = {:?}", getresultresult);

        // let before_latency = before.elapsed().as_nanos();

        let packet = &self.recv_buffer[0..recv_fromlen];

        let packet = match self.target {
            SocketAddr::V4(_) => {
                let ip_header_length = ((packet[0] & 0x0F) * 4) as usize;
                &packet[ip_header_length..]
            }
            SocketAddr::V6(_) => packet,
        };

        // let rx_time = self.time_reference.elapsed().as_nanos() as u64;
        let rx_time = Instant::now();
        // println!("recv_result: {}", result);
        // let last_error = WinSock::WSAGetLastError();
        // println!("{:?}", last_error);
        // println!("bytes_received: {}", bytes_received);
        // println!("{:?}", &recv_buffer[0..(bytes_received as usize)]);

        // let ip_header_length = ((packet[0] & 0x0F) * 4) as usize;
        // let icmp_packet = &packet[ip_header_length..];
        let icmp_packet = packet;

        let icmp_type = icmp_packet[0];
        // let icmp_code = icmp_packet[1];

        // println!(
        //     "icmp_type = {:?}, icmp_code = {}, identifier = {}, sequence = {}",
        //     icmp_type, icmp_code, icmp_identifier, icmp_sequence
        // );

        let echo_reply = match self.target {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(_) => 129,
        };

        if icmp_type != echo_reply {
            println!("Something not echo reply received {}", icmp_type);
        }

        // println!("icmp_packet = {:?}", icmp_packet);

        let identifier = u16::from_be_bytes(icmp_packet[4..6].try_into().unwrap());
        let sequence = u16::from_be_bytes(icmp_packet[6..8].try_into().unwrap());
        let timestamp = u64::from_be_bytes(icmp_packet[8..16].try_into().unwrap());
        // println!("identifier = {:?}", identifier);
        // println!("sequence = {:?}", sequence);
        // println!("timestamp = {:?}", timestamp);
        // let delta_nano = rx_time - timestamp;
        // let latency = Duration::from_nanos(delta_nano);
        // println!("delta_nano = {:?}", delta_nano);
        // println!("latency = {:?}", latency);
        // println!("before_latency = {:?}", before_latency);

        Some((addr, identifier, sequence, timestamp, rx_time))
    }
}

fn lookup_error(error_id: u32) -> Result<String, std::string::FromUtf16Error> {
    let mut str = PWSTR::null();
    let error_message = unsafe {
        FormatMessageW(
            Debug::FORMAT_MESSAGE_ALLOCATE_BUFFER
                | Debug::FORMAT_MESSAGE_FROM_SYSTEM
                | Debug::FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            error_id,
            0,
            #[allow(clippy::crosspointer_transmute)] // This is safe and required by the API
            std::mem::transmute(&mut str as *mut PWSTR),
            0,
            None,
        );
        let error_message = str.to_string();
        windows::Win32::Foundation::LocalFree(HLOCAL(str.as_ptr() as *mut c_void));
        error_message
    };
    Ok(error_message.unwrap())
}

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
            assert_eq!(
                addr.u.Byte,
                [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]
            );
        }
    }
}
