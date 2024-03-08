//! The actual walker

use crate::discover::{
    DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor, DistributionContext,
};
use crate::model::metadata::Distribution;
use crate::source::Source;
use futures::{stream, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use std::fmt::Debug;
use std::sync::Arc;
use url::ParseError;
use walker_common::progress::Progress;

#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

pub type DistributionFilter = Box<dyn Fn(&DistributionContext) -> bool>;

pub struct Walker<S: Source> {
    source: S,
    progress: Progress,
    distribution_filter: Option<DistributionFilter>,
}

impl<S: Source> Walker<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            progress: Progress::default(),
            distribution_filter: None,
        }
    }

    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.progress = progress;
        self
    }

    /// Set a filter for distributions.
    ///
    /// Each distribution from the metadata file will be passed to this function, if it returns `false`, the distribution
    /// will not even be fetched.
    pub fn with_distribution_filter<F>(mut self, distribution_filter: F) -> Self
    where
        F: Fn(&DistributionContext) -> bool + 'static,
    {
        self.distribution_filter = Some(Box::new(distribution_filter));
        self
    }

    fn collect_distributions(&self, distributions: Vec<Distribution>) -> Vec<DistributionContext> {
        distributions
            .into_iter()
            .flat_map(|distribution| {
                distribution
                    .rolie
                    .into_iter()
                    .flat_map(|rolie| rolie.feeds)
                    .map(|feed| DistributionContext::Feed(feed.url))
                    .chain(
                        distribution
                            .directory_url
                            .map(DistributionContext::Directory),
                    )
            })
            .filter(|distribution| {
                if let Some(filter) = &self.distribution_filter {
                    filter(distribution)
                } else {
                    true
                }
            })
            .collect()
    }

    pub async fn walk<V>(self, visitor: V) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata = self.source.load_metadata().await.map_err(Error::Source)?;

        let context = visitor
            .visit_context(&DiscoveredContext {
                metadata: &metadata,
            })
            .await
            .map_err(Error::Visitor)?;

        let distributions = self.collect_distributions(metadata.distributions);
        log::info!("processing {} distribution URLs", distributions.len());

        for distribution in distributions {
            log::info!("Walking directory URL: {:?}", distribution);
            let index = self
                .source
                .load_index(distribution)
                .await
                .map_err(Error::Source)?;

            let progress = self.progress.start(index.len());

            for advisory in index {
                log::debug!("  Discovered advisory: {advisory:?}");
                progress.set_message(
                    advisory
                        .url
                        .path()
                        .rsplit_once('/')
                        .map(|(_, s)| s)
                        .unwrap_or(advisory.url.as_str())
                        .to_string()
                        .into(),
                );
                visitor
                    .visit_advisory(&context, advisory)
                    .await
                    .map_err(Error::Visitor)?;
                progress.tick();
            }
        }

        Ok(())
    }

    pub async fn walk_parallel<V>(
        self,
        limit: usize,
        visitor: V,
    ) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata = self.source.load_metadata().await.map_err(Error::Source)?;
        let context = visitor
            .visit_context(&DiscoveredContext {
                metadata: &metadata,
            })
            .await
            .map_err(Error::Visitor)?;

        let context = Arc::new(context);
        let visitor = Arc::new(visitor);

        let distributions = self.collect_distributions(metadata.distributions);
        log::info!("processing {} distribution URLs", distributions.len());

        let advisories: Vec<_> = collect_advisories::<V, S>(&self.source, distributions)
            .try_collect()
            .await?;

        let size = advisories.len();
        log::info!("Discovered {size} advisories");

        stream::iter(self.progress.wrap_iter(size, advisories.into_iter()))
            .map(Ok)
            .try_for_each_concurrent(limit, |advisory| {
                log::debug!("Discovered advisory: {}", advisory.url);
                let context = context.clone();
                let visitor = visitor.clone();

                async move {
                    visitor
                        .visit_advisory(&context, advisory.clone())
                        .map_err(Error::Visitor)
                        .await
                }
            })
            .await?;

        Ok(())
    }
}

#[allow(clippy::needless_lifetimes)] // false positive
fn collect_sources<'s, V: DiscoveredVisitor, S: Source>(
    source: &'s S,
    discover_contexts: Vec<DistributionContext>,
) -> impl TryStream<Ok = impl Stream<Item = DiscoveredAdvisory>, Error = Error<V::Error, S::Error>> + 's
{
    stream::iter(discover_contexts).then(move |discover_context| async move {
        log::debug!("Walking: {}", discover_context.url());
        Ok(stream::iter(
            source
                .load_index(discover_context.clone())
                .await
                .map_err(Error::Source)?,
        ))
    })
}

fn collect_advisories<'s, V: DiscoveredVisitor + 's, S: Source>(
    source: &'s S,
    discover_contexts: Vec<DistributionContext>,
) -> impl TryStream<Ok = DiscoveredAdvisory, Error = Error<V::Error, S::Error>> + 's {
    collect_sources::<V, S>(source, discover_contexts)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}
