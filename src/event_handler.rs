use crate::ping::RecvError;

pub type GenericError = Box<dyn std::error::Error>;
pub type GenericResult = Result<(), GenericError>;

pub trait GlobalPingEventHandler {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize) -> GenericResult;

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration) -> GenericResult;

    fn on_error(&mut self, target: usize, seq: u64, error: &RecvError) -> GenericResult;

    fn on_timeout(&mut self, target: usize, seq: u64) -> GenericResult;
}

pub trait TargetPingEventHandler {
    fn on_sent(&mut self, seq: u64, length: usize) -> GenericResult;

    fn on_received(&mut self, seq: u64, rtt: std::time::Duration) -> GenericResult;

    fn on_error(&mut self, seq: u64, error: &RecvError) -> GenericResult;

    fn on_timeout(&mut self, seq: u64) -> GenericResult;
}
