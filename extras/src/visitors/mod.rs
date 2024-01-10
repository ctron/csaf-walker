//! Additional out-of-the-box visitors

#[cfg(any(feature = "csaf-walker", feature = "sbom-walker"))]
mod ignore;

#[cfg(any(feature = "csaf-walker", feature = "sbom-walker"))]
pub use ignore::*;
