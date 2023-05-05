//! The actual walker

use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::model::metadata::{Distribution, ProviderMetadata};
use reqwest::Url;
use std::fmt::Debug;
use url::ParseError;

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: std::fmt::Display + Debug,
{
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

pub struct Walker {
    url: Url,
    client: reqwest::Client,
}

impl Walker {
    pub fn new(url: Url, client: reqwest::Client) -> Self {
        Self { url, client }
    }

    pub async fn walk<V>(self, visitor: V) -> Result<(), Error<V::Error>>
    where
        V: DiscoveredVisitor,
    {
        let metadata: ProviderMetadata = self
            .client
            .get(self.url.clone())
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

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
            .client
            .get(dist.directory_url.join("index.txt")?)
            .send()
            .await?
            .text()
            .await?
            .lines()
            .into_iter()
            .map(|s| Url::parse(&format!("{}{s}", dist.directory_url)))
            .collect::<Result<_, _>>()?)
    }
}
