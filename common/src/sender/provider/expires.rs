use chrono::Utc;

/// Check if something expired or expires soon.
pub trait Expires {
    /// Check if the resource expires before the duration elapsed.
    fn expires_before(&self, duration: time::Duration) -> bool;
}

impl Expires for openid::TemporalBearerGuard {
    fn expires_before(&self, duration: time::Duration) -> bool {
        match self.expires_at() {
            Some(expires) => (expires - Utc::now()).num_seconds() <= duration.whole_seconds(),
            None => false,
        }
    }
}
