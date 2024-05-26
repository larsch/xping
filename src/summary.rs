use std::fmt::Write;

use serde_derive::Serialize;
use serde_with::{serde_as, DurationSecondsWithFrac};

#[serde_as]
#[derive(Serialize)]
pub struct Summary {
    pub hostname: String,
    pub address: std::net::IpAddr,
    pub packets_transmitted: u64,
    pub packets_received: u64,
    #[serde_as(as = "Option<DurationSecondsWithFrac<f64>>")]
    pub minimum_rtt: Option<std::time::Duration>,
    #[serde_as(as = "Option<DurationSecondsWithFrac<f64>>")]
    pub maximum_rtt: Option<std::time::Duration>,
    #[serde_as(as = "Option<DurationSecondsWithFrac<f64>>")]
    pub average_rtt: Option<std::time::Duration>,
    pub total_time: std::time::Duration,
}

impl Summary {
    pub fn as_text(&self) -> Result<String, std::fmt::Error> {
        let mut result = String::new();

        writeln!(&mut result, "\x1b[1m{} ({})\x1b[0m:", self.hostname, self.address)?;

        write!(
            &mut result,
            "{} packets transmitted, {} packets received",
            self.packets_transmitted, self.packets_received
        )?;
        if self.packets_transmitted > 0 {
            write!(
                &mut result,
                ", {:.1}% packet loss",
                100.0 - (self.packets_received as f64 / self.packets_transmitted as f64 * 100.0)
            )?;
        }
        write!(&mut result, ", time {:?}", self.total_time)?;
        if let Some(minimum_rtt) = self.minimum_rtt {
            write!(
                &mut result,
                "\nround-trip min/avg/max = {:?}/{:?}/{:?}",
                minimum_rtt,
                self.average_rtt.unwrap(),
                self.maximum_rtt.unwrap()
            )?;
        }
        writeln!(result)?;
        Ok(result)
    }

    pub fn as_csv(&self) -> Result<String, std::fmt::Error> {
        let mut result = String::new();
        writeln!(
            &mut result,
            "{},{},{},{},{},{},{},{}",
            self.hostname,
            self.address,
            self.packets_transmitted,
            self.packets_received,
            self.minimum_rtt.map_or("".to_owned(), |d| d.as_nanos().to_string()),
            self.average_rtt.map_or("".to_owned(), |d| d.as_nanos().to_string()),
            self.maximum_rtt.map_or("".to_owned(), |d| d.as_nanos().to_string()),
            self.total_time.as_nanos()
        )?;
        Ok(result)
    }
}
