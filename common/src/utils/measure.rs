//! Measuring the time of operations

use std::time::{Duration, SystemTime};

pub struct MeasureTime(SystemTime, bool);

impl MeasureTime {
    pub fn new(quiet: bool) -> Self {
        Self(SystemTime::now(), quiet)
    }
}

impl Drop for MeasureTime {
    fn drop(&mut self) {
        match self.0.elapsed() {
            Ok(duration) => {
                // truncate to seconds, good enough
                let duration = Duration::from_secs(duration.as_secs());
                if !self.1 {
                    println!("Processing took {}", humantime::format_duration(duration))
                } else {
                    log::info!("Processing took {}", humantime::format_duration(duration))
                }
            }
            Err(err) => log::info!("Unable to measure processing time: {err}"),
        }
    }
}
