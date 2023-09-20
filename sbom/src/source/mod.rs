//! Sources

mod dispatch;
mod http;

pub use dispatch::*;
pub use http::*;

use crate::discover::DiscoveredSbom;
use crate::model::metadata::SourceMetadata;
use crate::retrieve::RetrievedSbom;
use async_trait::async_trait;
use std::fmt::{Debug, Display};

/// A source of SBOM documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<SourceMetadata, Self::Error>;
    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error>;
    async fn load_sbom(&self, sbom: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error>;
}
