//! The actual walker

use crate::discover::{
    DiscoverContext, DiscoverContextType, DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor,
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

pub type DistributionFilter = Box<dyn Fn(&Distribution) -> bool>;

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
        F: Fn(&Distribution) -> bool + 'static,
    {
        self.distribution_filter = Some(Box::new(distribution_filter));
        self
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

        for distribution in metadata.distributions {
            if let Some(distribution_filter) = &self.distribution_filter {
                if !distribution_filter(&distribution) {
                    continue;
                }
            }

            let mut index = vec![];
            if let Some(directory_url) = &distribution.directory_url {
                log::info!("Walking directory URL: {:?}", directory_url.clone());
                index.append(
                    &mut self
                        .source
                        .load_index(DiscoverContext {
                            discover_context_type: DiscoverContextType::Directory,
                            url: directory_url.clone(),
                        })
                        .await
                        .map_err(Error::Source)?,
                );
            }
            if let Some(rolie) = distribution.rolie {
                for feed in rolie.feeds {
                    log::info!("Walking ROLIE feed: {:?}", feed.url);
                    index.append(
                        &mut self
                            .source
                            .load_index(DiscoverContext {
                                discover_context_type: DiscoverContextType::Feed,
                                url: feed.url.clone(),
                            })
                            .await
                            .map_err(Error::Source)?,
                    );
                }
            }
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

        let distributions = if let Some(distribution_filter) = self.distribution_filter {
            metadata
                .distributions
                .into_iter()
                .filter(|distribution| distribution_filter(distribution))
                .collect()
        } else {
            metadata.distributions
        };

        for distribution in distributions {
            let mut distribution_list = vec![];
            if let Some(directory_url) = distribution.directory_url {
                distribution_list.push(DiscoverContext {
                    discover_context_type: DiscoverContextType::Directory,
                    url: directory_url,
                })
            }
            if let Some(rolie) = distribution.rolie {
                for feed in rolie.feeds {
                    distribution_list.push(DiscoverContext {
                        discover_context_type: DiscoverContextType::Feed,
                        url: feed.url,
                    })
                }
            }
            let stream = collect_advisories::<V, S>(&self.source, distribution_list);
            let (_start, size) = stream.size_hint();
            let _progress = size.map(|size| self.progress.start(size));

            stream
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
        }

        Ok(())
    }
}

#[allow(clippy::needless_lifetimes)] // false positive
fn collect_sources<'s, V: DiscoveredVisitor, S: Source>(
    source: &'s S,
    discover_contexts: Vec<DiscoverContext>,
) -> impl TryStream<Ok = impl Stream<Item = DiscoveredAdvisory>, Error = Error<V::Error, S::Error>> + 's
{
    stream::iter(discover_contexts).then(move |discover_context| async move {
        log::debug!("Walking: {}", discover_context.url);
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
    discover_contexts: Vec<DiscoverContext>,
) -> impl TryStream<Ok = DiscoveredAdvisory, Error = Error<V::Error, S::Error>> + 's {
    collect_sources::<V, S>(source, discover_contexts)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}
