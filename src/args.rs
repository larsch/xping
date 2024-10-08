use clap::Parser;

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum DisplayMode {
    #[default]
    #[value(alias("a"))]
    Classic,
    #[value(alias("c"))]
    Char,
    #[value(alias("g"))]
    CharGraph,
    #[value(alias("d"))]
    Debug,
    #[value(alias("p"))]
    Plot,
    #[value(alias("n"))]
    None,
    #[value(alias("i"))]
    Influx,
    #[value(alias("l"))]
    Log,
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
#[command(version, about, long_about = "Ping utility", author, name = "xping")]
pub struct Args {
    /// Number of packets per second
    #[arg(short, long, conflicts_with("interval"))]
    pub rate: Option<u32>,

    /// Packet interval in milliseconds
    #[arg(short, long, default_value_t = 1000, conflicts_with("rate"))]
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
    #[arg(required = true)]
    pub target: Vec<String>,

    /// Display mode
    #[arg(short, long, default_value = "classic")]
    pub display: DisplayMode,

    /// Report sample size.
    ///
    /// Number of samples included in each printed reported. May alternative be
    /// specified using `report_interval` option.
    #[arg(short, long, default_value_t = 1, conflicts_with("report_interval"))]
    pub sample_size: usize,

    /// Report interval in seconds
    ///
    /// Alternative way to specify the sample size, i.e. how many samples are
    /// included in each printed report.
    #[arg(long, conflicts_with("sample_size"))]
    pub report_interval: Option<f64>,

    /// Time to live
    #[arg(short, long, default_value_t = 64)]
    pub ttl: u8,

    /// API to use
    #[cfg(windows)]
    #[arg(long, default_value = "iphelper")]
    pub api: Api,

    // API to use
    #[cfg(not(windows))]
    #[arg(long, default_value = "icmp-socket")]
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

    /// Target all resolved addresses
    #[arg(short, long)]
    pub all: bool,
}
