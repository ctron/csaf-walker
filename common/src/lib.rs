#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

pub mod changes;
pub mod compression;
pub mod fetcher;
pub mod locale;
pub mod progress;
pub mod report;
pub mod retrieve;
pub mod scoop;
pub mod sender;
pub mod since;
pub mod source;
pub mod store;
pub mod utils;

#[cfg(feature = "openpgp")]
pub mod validate;

#[cfg(feature = "clap")]
pub mod cli;
