//! The actual walker

use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::fetcher::{self, Fetcher, Json, Text};
use crate::model::metadata::{Distribution, ProviderMetadata};
use futures::{stream, Stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use reqwest::Url;
use std::fmt::Debug;
use std::sync::Arc;
use url::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: std::fmt::Display + Debug,
{
    #[error("Fetch error: {0}")]
    Fetch(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

pub struct Walker {
    url: Url,
    fetcher: Fetcher,
}

impl Walker {
    pub fn new(url: Url, fetcher: Fetcher) -> Self {
        Self { url, fetcher }
    }

    async fn load_index<V>(
        fetcher: &Fetcher,
        dist: &Distribution,
    ) -> Result<Vec<Url>, Error<V::Error>>
    where
        V: DiscoveredVisitor,
    {
        Ok(fetcher
            .fetch::<Text>(dist.directory_url.join("index.txt")?)
            .await?
            .into_inner()
            .lines()
            .map(|s| Url::parse(&format!("{}{s}", dist.directory_url)))
            .collect::<Result<_, _>>()?)
    }

    pub async fn walk<V>(self, visitor: V) -> Result<(), Error<V::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata = self
            .fetcher
            .fetch::<Json<ProviderMetadata>>(self.url.clone())
            .await?
            .into_inner();

        let context = visitor
            .visit_context(&metadata)
            .await
            .map_err(Error::Visitor)?;

        for source in metadata.distributions {
            log::debug!("Walking: {}", source.directory_url);
            for url in Self::load_index::<V>(&self.fetcher, &source).await? {
                log::debug!("  Discovered advisory: {url}");
                visitor
                    .visit_advisory(&context, DiscoveredAdvisory { url })
                    .await
                    .map_err(Error::Visitor)?;
            }
        }

        Ok(())
    }

    pub async fn walk_parallel<V>(self, limit: usize, visitor: V) -> Result<(), Error<V::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata = self
            .fetcher
            .fetch::<Json<ProviderMetadata>>(self.url.clone())
            .await?
            .into_inner();

        let context = visitor
            .visit_context(&metadata)
            .await
            .map_err(Error::Visitor)?;

        let context = Arc::new(context);
        let visitor = Arc::new(visitor);

        let fetcher = self.fetcher;

        collect_urls::<V>(&fetcher, metadata.distributions)
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

fn collect_sources<V: DiscoveredVisitor>(
    fetcher: &Fetcher,
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = impl Stream<Item = Url>, Error = Error<V::Error>> {
    let fetcher = fetcher.clone();
    stream::iter(distributions).then(move |source| {
        let fetcher = fetcher.clone();
        async move {
            log::debug!("Walking: {}", source.directory_url);
            Ok(stream::iter(
                Walker::load_index::<V>(&fetcher, &source).await?,
            ))
        }
    })
}

fn collect_urls<V: DiscoveredVisitor>(
    fetcher: &Fetcher,
    distributions: Vec<Distribution>,
) -> impl TryStream<Ok = Url, Error = Error<V::Error>> {
    collect_sources::<V>(fetcher, distributions)
        .map_ok(|s| s.map(Ok))
        .try_flatten()
}
