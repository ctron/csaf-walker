//! The actual walker

use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::fetcher;
use crate::fetcher::{Fetcher, Json, Text};
use crate::model::metadata::{Distribution, ProviderMetadata};
use reqwest::Url;
use std::fmt::Debug;
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
            for url in self.load_index::<V>(&source).await? {
                log::debug!("  Discovered advisory: {url}");
                visitor
                    .visit_advisory(&context, DiscoveredAdvisory { url })
                    .await
                    .map_err(Error::Visitor)?;
            }
        }

        Ok(())
    }

    async fn load_index<V>(&self, dist: &Distribution) -> Result<Vec<Url>, Error<V::Error>>
    where
        V: DiscoveredVisitor,
    {
        Ok(self
            .fetcher
            .fetch::<Text>(dist.directory_url.join("index.txt")?)
            .await?
            .into_inner()
            .lines()
            .into_iter()
            .map(|s| Url::parse(&format!("{}{s}", dist.directory_url)))
            .collect::<Result<_, _>>()?)
    }
}
