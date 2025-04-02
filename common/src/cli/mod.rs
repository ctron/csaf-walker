//! Command line helpers
pub mod client;
pub mod runner;

#[cfg(feature = "openpgp")]
pub mod validation;

#[cfg(feature = "cli")]
pub mod log;

pub trait CommandDefaults {
    fn progress(&self) -> bool {
        true
    }
}
