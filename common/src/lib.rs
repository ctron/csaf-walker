#![deny(clippy::unwrap_used)]

pub mod changes;
pub mod compression;
pub mod fetcher;
pub mod progress;
pub mod report;
pub mod retrieve;
pub mod sender;
pub mod since;
pub mod source;
pub mod utils;
pub mod validate;

#[cfg(feature = "clap")]
pub mod cli;
