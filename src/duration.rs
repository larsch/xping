use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParseDurationError {}

impl std::fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "invalid duration")
    }
}

impl std::fmt::Debug for ParseDurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "invalid duration")
    }
}

/// Parse duration strings like "200ms", "17s", "2m30s", "3h", "4d" into `Duration`.
pub fn parse_duration(s: &str) -> Result<Duration, ParseDurationError> {
    let mut num = 0;
    let mut unit = Duration::from_secs(0);
    let chars = s.chars().chain(['0']);
    let mut unit_str = String::new();
    for c in chars {
        println!("c: {}", c);
        if c.is_ascii_digit() {
            if !unit_str.is_empty() {
                println!("unit_str: {}, num: {}", unit_str, num);
                match unit_str.as_str() {
                    "ns" => unit += Duration::from_nanos(num),
                    "µs" | "us" => unit += Duration::from_micros(num),
                    "ms" => unit += Duration::from_millis(num),
                    "s" => unit += Duration::from_secs(num),
                    "m" => unit += Duration::from_secs(num * 60),
                    "h" => unit += Duration::from_secs(num * 3600),
                    "d" => unit += Duration::from_secs(num * 86400),
                    _ => return Err(ParseDurationError {}),
                }
                num = 0;
                unit_str.clear();
            }
            num = num * 10 + c.to_digit(10).unwrap() as u64;
        } else {
            unit_str.push(c);
        }
    }
    if unit_str.is_empty() && num != 0 {
        Err(ParseDurationError {})
    } else {
        Ok(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("4ns").unwrap(), Duration::from_nanos(4));
        assert_eq!(parse_duration("4us").unwrap(), Duration::from_micros(4));
        assert_eq!(parse_duration("4µs").unwrap(), Duration::from_micros(4));
        assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("1"), Err(ParseDurationError {}));
        assert_eq!(parse_duration("1s1"), Err(ParseDurationError {}));
        assert_eq!(parse_duration("1m1"), Err(ParseDurationError {}));
        assert_eq!(parse_duration("1h1"), Err(ParseDurationError {}));
        assert_eq!(parse_duration("1d1"), Err(ParseDurationError {}));

        assert_eq!(parse_duration("1ms").unwrap(), Duration::from_millis(1));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("1d1h").unwrap(), Duration::from_secs(90000));
    }
}
