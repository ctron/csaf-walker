pub mod openpgp;
pub mod source;

use std::time::SystemTime;

#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct ValidationOptions {
    /// time for policy checks
    pub validation_date: Option<SystemTime>,
}

impl ValidationOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validation_date(mut self, validation_date: impl Into<SystemTime>) -> Self {
        self.validation_date = Some(validation_date.into());
        self
    }
}
