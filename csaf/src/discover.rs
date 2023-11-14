//! Discovering

use crate::model::metadata::ProviderMetadata;
use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use std::time::SystemTime;
use url::Url;
use walker_common::utils::url::Urlify;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredAdvisory {
    /// The URL of the advisory
    pub url: Url,
    /// The "last changed" date from the change information, if there was some.
    pub modified: Option<SystemTime>,
}

impl Urlify for DiscoveredAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }
}

#[derive(Debug)]
pub struct DiscoveredContext<'c> {
    pub metadata: &'c ProviderMetadata,
}

/// Visiting discovered advisories
#[async_trait(?Send)]
pub trait DiscoveredVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
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
    E: std::fmt::Display + Debug,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &DiscoveredContext,
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
