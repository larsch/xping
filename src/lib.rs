pub mod display;
pub mod ping;

pub trait PingEventHandler {
    fn on_sent(&mut self, sequence: u64);
    fn on_received(&mut self, bucket_index: u64, round_trip_time: std::time::Duration);
    fn on_error(&mut self, sequence: u64);
    fn on_timeout(&mut self, sequence: u64);
}
