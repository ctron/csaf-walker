//! Discovering

use crate::model::metadata::{Distribution, ProviderMetadata};
use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;
use url::Url;
use walker_common::utils::url::Urlify;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredAdvisory {
    /// A reference to the distribution information
    pub distribution: Arc<Distribution>,
    /// The URL of the advisory
    pub url: Url,
    /// The "last changed" date from the change information
    pub modified: SystemTime,
}

/// Get a document as [`DiscoveredAdvisory`]
pub trait AsDiscovered: Debug {
    fn as_discovered(&self) -> &DiscoveredAdvisory;
}

impl AsDiscovered for DiscoveredAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        self
    }
}

impl Urlify for DiscoveredAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    // fn relative_base_and_url(&self) -> Option<(&Url, String)> {
    //     // let directory_url = &self.distribution.directory_url.clone().unwrap();
    //     // directory_url
    //     //     .make_relative(&self.url)
    //     //     .map(|relative| (directory_url, relative))
    //     // if let Some(directory_url) = &self.distribution.directory_url {
    //     //     directory_url
    //     //         .make_relative(&self.url)
    //     //         .map(|relative| (directory_url.clone(), relative))
    //     // } else {
    //     //     Option::None
    //     // }
    //     // self.distribution
    //     //     .directory_url
    //     //     .make_relative(&self.url)
    //     //     .map(|relative| (&self.distribution.directory_url.unwrap(), relative))
    // }
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
