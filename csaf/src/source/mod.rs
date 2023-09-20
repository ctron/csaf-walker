//! Sources

mod dispatch;
mod file;
mod http;

pub use dispatch::*;
pub use file::*;
pub use http::*;

use crate::discover::DiscoveredAdvisory;
use crate::model::metadata::{Distribution, ProviderMetadata};
use crate::retrieve::RetrievedAdvisory;
use async_trait::async_trait;
use std::fmt::{Debug, Display};

/// A source of CSAF documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error>;
    async fn load_index(
        &self,
        distribution: &Distribution,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error>;
    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error>;
}
