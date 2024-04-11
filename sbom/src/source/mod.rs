//! Sources

mod dispatch;
mod file;
mod http;

pub use self::http::*;
pub use dispatch::*;
pub use file::*;

use crate::{
    discover::{DiscoverConfig, DiscoveredSbom},
    model::metadata::SourceMetadata,
    retrieve::RetrievedSbom,
};
use anyhow::bail;
use async_trait::async_trait;
use fluent_uri::Uri;
use std::fmt::{Debug, Display};
use url::Url;
use walker_common::fetcher::{Fetcher, FetcherOptions};

/// A source of SBOM documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<SourceMetadata, Self::Error>;
    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error>;
    async fn load_sbom(&self, sbom: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error>;
}

pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    fetcher: impl Into<FetcherOptions>,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();
    let source = discover.source;

    match Uri::parse(&source) {
        Ok(uri) => {
            match uri.scheme().map(|s| s.as_str()) {
                Some("file") => {
                    let source = uri.path().as_str();
                    Ok(FileSource::new(source, FileOptions::new().since(discover.since))?.into())
                }
                Some(_scheme) => {
                    let fetcher = Fetcher::new(fetcher.into()).await?;
                    Ok(HttpSource::new(
                        Url::parse(&source)?,
                        fetcher,
                        HttpOptions::new().since(discover.since).keys(discover.keys),
                    )
                    .into())
                }
                None => {
                    bail!("Failed to parse '{source}' as URL. For SBOMs there is no domain-based lookup");
                }
            }
        }
        Err(err) => {
            bail!(
                "Failed to parse '{source}' as URL. For SBOMs there is no domain-based lookup: {err}"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use crate::discover::DiscoverConfig;
    use crate::source::new_source;
    use walker_common::fetcher::FetcherOptions;

    #[tokio::test]
    pub async fn test_file_source() {
        let result = new_source(
            DiscoverConfig {
                source: "file:/".to_string(),
                since: None,
                keys: vec![],
            },
            FetcherOptions::default(),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    pub async fn test_http_source() {
        let result = new_source(
            DiscoverConfig {
                source: "https://foo.bar/baz".to_string(),
                since: None,
                keys: vec![],
            },
            FetcherOptions::default(),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    pub async fn test_invalid_source() {
        let result = new_source(
            DiscoverConfig {
                source: "/var/files".to_string(),
                since: None,
                keys: vec![],
            },
            FetcherOptions::default(),
        )
        .await;

        assert!(result.is_err());
    }
}
