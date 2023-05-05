//! Discovering

use crate::model::metadata::ProviderMetadata;
use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredAdvisory {
    pub url: Url,
}

/// Visiting discovered advisories
#[async_trait(?Send)]
pub trait DiscoveredVisitor {
    type Error: std::error::Error + Debug;
    type Context;

    async fn visit_context(
        &self,
        metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error>;

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
impl<F, E, Fut> DiscoveredVisitor for F
where
    F: Fn(DiscoveredAdvisory) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::error::Error,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        self(advisory).await
    }
}
