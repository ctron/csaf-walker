use std::time::SystemTime;

/// Check if something expired or expires soon.
pub trait Expires {
    /// Check if the resource expires before the duration elapsed.
    fn expires_before(&self, duration: time::Duration) -> bool {
        match self.expires_in() {
            Some(expires) => expires <= duration,
            None => false,
        }
    }

    /// Get the duration until this resource expires. This may be negative.
    fn expires_in(&self) -> Option<time::Duration> {
        self.expires()
            .map(|expires| expires - time::OffsetDateTime::now_utc())
    }

    /// Get the timestamp when the resource expires.
    fn expires(&self) -> Option<time::OffsetDateTime>;
}

impl Expires for openid::Bearer {
    fn expires(&self) -> Option<time::OffsetDateTime> {
        self.expires.map(|e| {
            let expires: SystemTime = e.into();
            time::OffsetDateTime::from(expires)
        })
    }
}

impl Expires for time::OffsetDateTime {
    fn expires(&self) -> Option<time::OffsetDateTime> {
        Some(*self)
    }
}
