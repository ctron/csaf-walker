//! Sources

mod dispatch;
mod http;

pub use dispatch::*;
pub use http::*;

use crate::discover::DiscoveredSbom;
use async_trait::async_trait;
use std::fmt::{Debug, Display};

/// A source of SBOM documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error>;
    // async fn load_sbom(&self, advisory: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error>;
}
