mod sockaddr;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::PingProtocol;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::PingProtocol;

type PingResponse = (std::net::SocketAddr, u16, u16, u64, std::time::Instant);
