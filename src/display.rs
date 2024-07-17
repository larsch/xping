// #![allow(unused_variables)]

use std::net::IpAddr;

pub mod appendable;

mod classic;
pub use classic::ClassicDisplayMode;

mod log;
pub use log::LogDisplay;

mod char;
pub use char::CharDisplayMode;

mod char_graph;
pub use char_graph::CharGraphDisplayMode;

mod debug;
pub use debug::DebugDisplayMode;

mod plot;
pub use plot::HorizontalPlotDisplayMode;

mod none;
pub use none::NoneDisplayMode;

mod influx;
pub use influx::InfluxLineProtocolDisplayMode;

/// Generic interface for displaying ping results
pub trait DisplayModeTrait: crate::event_handler::GlobalPingEventHandler {
    /// Create a new display
    fn new(columns: u16, rows: u16) -> Self
    where
        Self: Sized;

    /// Add a target to the display
    ///
    /// Invoked when a new target is added to the ping command during initialization.
    fn add_target(&mut self, index: usize, target: &IpAddr, hostname: &str) -> std::io::Result<()>;

    /// Close the display
    fn close(&mut self) -> std::io::Result<()>;
}
