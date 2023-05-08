use std::time::{Duration, SystemTime};

pub struct MeasureTime(SystemTime);

impl MeasureTime {
    pub fn new() -> Self {
        Self(SystemTime::now())
    }
}

impl Drop for MeasureTime {
    fn drop(&mut self) {
        match self.0.elapsed() {
            Ok(duration) => {
                // truncate to seconds, good enough
                let duration = Duration::from_secs(duration.as_secs());
                log::info!("Processing took {}", humantime::format_duration(duration))
            }
            Err(err) => log::info!("Unable to measure processing time: {err}"),
        }
    }
}
