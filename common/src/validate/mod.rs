pub mod openpgp;
pub mod source;

use std::time::SystemTime;

#[derive(Clone, Debug, Default)]
pub struct ValidationOptions {
    /// time for policy checks
    pub validation_date: Option<SystemTime>,
}
