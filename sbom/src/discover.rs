//! Discovering

use crate::model::metadata::SourceMetadata;
use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::time::SystemTime;
use url::Url;
use walker_common::utils::url::Urlify;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSbom {
    /// The URL of the SBOM
    pub url: Url,
    /// The "last changed" date from the change information
    pub modified: SystemTime,
}

impl Urlify for DiscoveredSbom {
    fn url(&self) -> &Url {
        &self.url
    }
}

#[derive(Debug)]
pub struct DiscoveredContext<'c> {
    pub metadata: &'c SourceMetadata,
}

impl<'c> Deref for DiscoveredContext<'c> {
    type Target = SourceMetadata;

    fn deref(&self) -> &Self::Target {
        &self.metadata
    }
}

/// Visiting discovered SBOMs
#[async_trait(?Send)]
pub trait DiscoveredVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error>;

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
impl<F, E, Fut> DiscoveredVisitor for F
where
    F: Fn(DiscoveredSbom) -> Fut,
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

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        sbom: DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        self(sbom).await
    }
}
