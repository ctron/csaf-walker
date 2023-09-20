//! Discovering

use async_trait::async_trait;
use std::fmt::Debug;
use std::future::Future;
use std::time::SystemTime;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSbom {
    /// The URL of the SBOM
    pub url: Url,
    /// The "last changed" date from the change information, if there was some.
    pub modified: Option<SystemTime>,
}

/// Visiting discovered SBOMs
#[async_trait(?Send)]
pub trait DiscoveredVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    async fn visit_sbom(&self, sbom: DiscoveredSbom) -> Result<(), Self::Error>;
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

    async fn visit_sbom(&self, sbom: DiscoveredSbom) -> Result<(), Self::Error> {
        self(sbom).await
    }
}
