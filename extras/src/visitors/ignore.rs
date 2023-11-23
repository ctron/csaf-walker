//! Ignore discovered content

use async_trait::async_trait;
use std::collections::HashSet;
use walker_common::utils::url::Urlify;

#[cfg(feature = "sbom-walker")]
pub(crate) mod sbom {
    pub use crate::sbom::discover::{DiscoveredContext, DiscoveredSbom, DiscoveredVisitor};
}

#[cfg(feature = "csaf-walker")]
pub(crate) mod csaf {
    pub use crate::csaf::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
}

/// A visitor which can ignore discovered content.
pub struct Ignore<'s, V> {
    visitor: V,
    only: HashSet<&'s str>,
}

impl<'s, V> Ignore<'s, V> {
    pub fn new(visitor: V, only: impl IntoIterator<Item = &'s str>) -> Self {
        Self {
            visitor,
            only: HashSet::from_iter(only),
        }
    }

    /// check if the item should be ignored
    ///
    /// returns `true` if the item should be ignored, `false` otherwise.
    fn ignore(&self, url: &impl Urlify) -> bool {
        let url = url.url();
        let name = url
            .path_segments()
            .and_then(|path| path.last())
            .unwrap_or(url.path());

        !self.only.is_empty() && !self.only.contains(name)
    }
}

#[cfg(feature = "sbom-walker")]
#[async_trait(?Send)]
impl<'s, V: sbom::DiscoveredVisitor> sbom::DiscoveredVisitor for Ignore<'s, V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &sbom::DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        sbom: sbom::DiscoveredSbom,
    ) -> Result<(), Self::Error> {
        if !self.ignore(&sbom) {
            self.visitor.visit_sbom(context, sbom).await?;
        }

        Ok(())
    }
}

#[cfg(feature = "csaf-walker")]
#[async_trait(?Send)]
impl<'s, V: csaf::DiscoveredVisitor> csaf::DiscoveredVisitor for Ignore<'s, V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &csaf::DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        csaf: csaf::DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        if !self.ignore(&csaf) {
            self.visitor.visit_advisory(context, csaf).await?;
        }

        Ok(())
    }
}
