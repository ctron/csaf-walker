use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use std::collections::HashSet;

/// A visitor, skipping advisories for existing files.
pub struct FilteringVisitor<V: DiscoveredVisitor> {
    pub visitor: V,

    pub config: FilterConfig,
}

#[non_exhaustive]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    /// A set of distributions to ignore
    ///
    /// **NOTE:** The distributions will still be discovered, as this is a post-discovery visitor. If you want to
    /// even skip discovering the source, use [`crate::walker::Walker::with_distribution_filter`].
    pub ignored_distributions: HashSet<String>,
    pub ignored_prefixes: Vec<String>,
    pub only_prefixes: Vec<String>,
}

impl FilterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ignored_distributions<I>(mut self, ignored_distributions: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.ignored_distributions = HashSet::from_iter(ignored_distributions);
        self
    }

    pub fn add_ignored_distribution(mut self, ignored_distribution: impl Into<String>) -> Self {
        self.ignored_distributions
            .insert(ignored_distribution.into());
        self
    }

    pub fn extend_ignored_distributions<I>(mut self, ignored_distributions: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.ignored_distributions.extend(ignored_distributions);
        self
    }

    pub fn ignored_prefixes<I>(mut self, ignored_prefixes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.ignored_prefixes = Vec::from_iter(ignored_prefixes);
        self
    }

    pub fn add_ignored_prefix(mut self, ignored_prefix: impl Into<String>) -> Self {
        self.ignored_prefixes.push(ignored_prefix.into());
        self
    }

    pub fn extend_ignored_prefixes<I>(mut self, ignored_prefixes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.ignored_prefixes.extend(ignored_prefixes);
        self
    }

    pub fn only_prefixes<I>(mut self, only_prefixes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.only_prefixes = Vec::from_iter(only_prefixes);
        self
    }

    pub fn add_only_prefix(mut self, only_prefix: impl Into<String>) -> Self {
        self.only_prefixes.push(only_prefix.into());
        self
    }

    pub fn extend_only_prefixes<I>(mut self, only_prefixes: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        self.only_prefixes.extend(only_prefixes);
        self
    }
}

impl<V: DiscoveredVisitor> DiscoveredVisitor for FilteringVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        discovered: &DiscoveredContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(discovered).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        // ignore distributions

        if self
            .config
            .ignored_distributions
            .contains(advisory.context.url().as_str())
        {
            return Ok(());
        };
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
