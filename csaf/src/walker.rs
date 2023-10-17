//! The actual walker

use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
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

pub struct Walker<S: Source> {
    source: S,
    progress: Progress,
    distribution_filter: Option<Box<dyn Fn(&Distribution) -> bool>>,
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

    pub fn with_distribution_filter(
        mut self,
        distribution_filter: Box<dyn Fn(&Distribution) -> bool>,
    ) -> Self {
        self.distribution_filter = Some(distribution_filter);
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
            log::debug!("Walking: {}", distribution.directory_url);
            let index = self
                .source
                .load_index(&distribution)
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

        let distributions = if let Some(distribution_filter) = self.distribution_filter {
            metadata
                .distributions
                .into_iter()
                .filter(|distribution| distribution_filter(distribution))
                .collect()
        } else {
            metadata.distributions
        };

        collect_advisories::<V, S>(&self.source, distributions)
            .try_for_each_concurrent(limit, |advisory| {
                log::debug!("Discovered advisory: {}", advisory.url);
                let context = context.clone();
                let visitor = visitor.clone();

                async move {
                    visitor
                        .visit_advisory(&context, advisory)
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
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = impl Stream<Item = DiscoveredAdvisory>, Error = Error<V::Error, S::Error>> + 's
{
    stream::iter(distributions).then(move |distribution| async move {
        log::debug!("Walking: {}", distribution.directory_url);
        Ok(stream::iter(
            source
                .load_index(&distribution)
                .await
                .map_err(Error::Source)?,
        ))
    })
}

fn collect_advisories<'s, V: DiscoveredVisitor + 's, S: Source>(
    source: &'s S,
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = DiscoveredAdvisory, Error = Error<V::Error, S::Error>> + 's {
    collect_sources::<V, S>(source, distributions)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}
