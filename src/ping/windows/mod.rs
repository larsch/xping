mod cmsghdr;
mod icmp_socket;

#[cfg(feature = "iphelper")]
pub mod iphelper;

#[cfg(feature = "iphelper")]
pub use iphelper::IpHelperApi;

pub use icmp_socket::IcmpSocketApi;
use windows::Win32::Networking::WinSock;

use std::net::{Ipv4Addr, Ipv6Addr};

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
