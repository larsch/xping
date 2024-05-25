use clap::Parser;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum DisplayMode {
    #[default]
    Classic,
    Char,
    Dumb,
    CharGraph,
    Debug,
    None,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum SummaryFormat {
    #[default]
    Text,
    Json,
    Csv,
    None,
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum Api {
    /// Use ICMP datagram sockets
    #[default]
    IcmpSocket,
    /// Use Windows IP Helper API
    #[cfg(windows)]
    #[cfg(feature = "iphelper")]
    Iphelper,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Ping utility", author, name = "mping")]
pub struct Args {
    /// Number of packets per second
    #[arg(short, long)]
    pub rate: Option<u32>,

    /// Packet interval in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    pub interval: u64,

    /// Number of attempts (default infinite)
    #[arg(short, long)]
    pub count: Option<u32>,

    /// Timeout waiting for response in milliseconds
    #[arg(short = 'w', long, default_value_t = 1000)]
    pub timeout: u64,

    /// Length of ICMP payload in bytes
    #[arg(short, long, default_value_t = 64)]
    pub length: usize,

    /// Address or name of target host
    #[arg()]
    pub target: String,

    /// Display mode
    #[arg(short, long, default_value = "classic")]
    pub display: DisplayMode,

    /// Time to live
    #[arg(short, long, default_value_t = 64)]
    pub ttl: u8,

    /// API to use
    #[arg(short, long, default_value = "icmp-socket")]
    pub api: Api,

    #[command(flatten)]
    pub force_ip: ForceIp,

    #[arg(long, default_value = "text")]
    pub summary: SummaryFormat,

    #[cfg(debug_assertions)]
    #[arg(long, hide = true)]
    pub update_readme: bool,
}

#[derive(Parser, Debug)]
#[group(multiple(false))]
pub struct ForceIp {
    /// Force using IPv4
    #[arg(short = '4', long)]
    pub ipv4: bool,

    /// Force using IPv6
    #[arg(short = '6', long)]
    pub ipv6: bool,
}
