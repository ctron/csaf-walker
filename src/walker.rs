//! The actual walker

use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::model::metadata::Distribution;
use crate::source::Source;
use futures::{stream, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use reqwest::Url;
use std::fmt::Debug;
use std::sync::Arc;
use url::ParseError;

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
}

impl<S: Source> Walker<S> {
    pub fn new(source: S) -> Self {
        Self { source }
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
            log::debug!("Walking: {}", distribution.directory_url);
            for url in self
                .source
                .load_index(&distribution)
                .await
                .map_err(Error::Source)?
            {
                log::debug!("  Discovered advisory: {url}");
                visitor
                    .visit_advisory(&context, DiscoveredAdvisory { url })
                    .await
                    .map_err(Error::Visitor)?;
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

        collect_urls::<V, S>(&self.source, metadata.distributions)
            .try_for_each_concurrent(limit, |url| {
                log::debug!("Discovered advisory: {url}");
                let context = context.clone();
                let visitor = visitor.clone();

                async move {
                    visitor
                        .visit_advisory(&context, DiscoveredAdvisory { url })
                        .map_err(Error::Visitor)
                        .await
                }
            })
            .await?;

        Ok(())
    }
}

fn collect_sources<'s, V: DiscoveredVisitor, S: Source>(
    source: &'s S,
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = impl Stream<Item = Url>, Error = Error<V::Error, S::Error>> + 's {
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

fn collect_urls<'s, V: DiscoveredVisitor, S: Source>(
    source: &'s S,
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = Url, Error = Error<V::Error, S::Error>> + 's {
    collect_sources::<V, S>(source, distributions)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}
