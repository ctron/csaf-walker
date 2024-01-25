use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use async_trait::async_trait;
use std::collections::HashSet;

/// A visitor, skipping advisories for existing files.
pub struct FilteringVisitor<V: DiscoveredVisitor> {
    pub visitor: V,

    pub config: FilterConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    pub ignored_distributions: HashSet<String>,
    pub ignored_prefixes: Vec<String>,
    pub only_prefixes: Vec<String>,
}

#[async_trait(?Send)]
impl<V: DiscoveredVisitor> DiscoveredVisitor for FilteringVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        discovered: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(discovered).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        // ignore distributions

        if let Some(directory_url) = &advisory.distribution.directory_url {
            if self
                .config
                .ignored_distributions
                .contains(directory_url.as_str())
            {
                return Ok(());
            }
        };

        // if self.config.ignored_distributions.contains(
        //     advisory
        //         .distribution
        //         .directory_url
        //         .clone()
        //         .unwrap()
        //         .as_str(),
        // ) {
        //     return Ok(());
        // }

        // eval name

        let name = advisory
            .url
            .path_segments()
            .and_then(|seg| seg.last())
            .unwrap_or(advisory.url.path());

        // "ignore" prefix

        for n in &self.config.ignored_prefixes {
            if name.starts_with(n.as_str()) {
                return Ok(());
            }
        }

        // "only" prefix

        for n in &self.config.only_prefixes {
            if !name.starts_with(n.as_str()) {
                return Ok(());
            }
        }

        // ok to proceed

        self.visitor.visit_advisory(context, advisory).await
    }
}
