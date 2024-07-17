use crate::ping::RecvError;

pub trait GlobalPingEventHandler {
    fn on_sent(&mut self, target: usize, seq: u64, length: usize);

    fn on_received(&mut self, target: usize, seq: u64, rtt: std::time::Duration);

    fn on_error(&mut self, target: usize, seq: u64, error: &RecvError);

    fn on_timeout(&mut self, target: usize, seq: u64);
}

pub trait TargetPingEventHandler {
    fn on_sent(&mut self, seq: u64, length: usize);

    fn on_received(&mut self, seq: u64, rtt: std::time::Duration);

    fn on_error(&mut self, seq: u64, error: &RecvError);

    fn on_timeout(&mut self, seq: u64);
}
