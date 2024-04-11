//! Sources

mod descriptor;
mod dispatch;
mod file;
mod http;

pub use descriptor::*;
pub use dispatch::*;
pub use file::*;
pub use http::*;

use crate::{
    discover::{DiscoverConfig, DiscoveredAdvisory, DistributionContext},
    model::metadata::ProviderMetadata,
    retrieve::RetrievedAdvisory,
};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::str::FromStr;
use walker_common::fetcher::FetcherOptions;

/// A source of CSAF documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error>;

    async fn load_index(
        &self,
        context: DistributionContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error>;

    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error>;
}

/// A common way to create a new CSAF source.
pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    fetcher: impl Into<FetcherOptions>,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();

    let descriptor = SourceDescriptor::from_str(&discover.source)?;
    descriptor.into_source(discover, fetcher.into()).await
}
