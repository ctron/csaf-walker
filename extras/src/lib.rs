#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

pub mod visitors;

#[cfg(feature = "sbom-walker")]
pub use sbom_walker as sbom;

#[cfg(feature = "csaf-walker")]
pub use csaf_walker as csaf;
