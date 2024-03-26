//! Sources

mod dispatch;
mod file;
mod http;

pub use dispatch::*;
pub use file::*;
pub use http::*;

use crate::discover::{DiscoveredAdvisory, DistributionContext};
use crate::model::metadata::ProviderMetadata;
use crate::retrieve::RetrievedAdvisory;
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::time::SystemTime;
use url::Url;
use walker_common::fetcher::Fetcher;

/// A source of CSAF documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error>;

    async fn load_index(
        &self,
        context: DistributionContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error>;

    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error>;
}

pub struct DiscoverConfig {
    /// The URL to locate the provider metadata or as a base domain, in order to facilitate automatic querying of provider metadata URL..
    pub source: String,

    /// Only report documents which have changed since the provided date. If a document has no
    /// change information, or this field is [`None`], it wil always be reported.
    pub since: Option<SystemTime>,
}

impl DiscoverConfig {
    pub fn with_since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

pub async fn input_string_dispatch(
    discover: DiscoverConfig,
    fetcher: Fetcher,
) -> anyhow::Result<DispatchSource> {
    let url_parse_result = Url::parse(discover.source.as_str());
    if let Ok(url) = url_parse_result.clone() {
        log::info!("The URl {:?}", url.clone());
        if url.scheme() == "https" {
            // handle direct URL case
            log::info!("Fully provided discovery URL: {}", discover.source.clone());
            return Ok(HttpSource::new(
                url.to_string(),
                fetcher,
                HttpOptions::new().since(discover.since),
            )
            .into());
        }
        // When the scheme of the input URL is "http" or "ftp", it should be interpreted as a host string.
        if (url.scheme() == "http") || (url.scheme() == "ftp") {
            if let Some(host_str) = url.host_str() {
                return Ok(HttpSource::new(
                    host_str.to_string(),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into());
            }
        }
    }

    if let Err(e) = url_parse_result.clone() {
        match e {
            url::ParseError::RelativeUrlWithoutBase => {
                log::info!("The URl does not have scheme, will treat it as base domain");
                return Ok(HttpSource::new(
                    discover.source.clone(),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into());
            }
            _ => {
                return Err(anyhow::Error::msg(format!(
                    "This is not a standard URL {}, please check again carefully. : {:?}",
                    discover.source.clone(),
                    e
                )))
            }
        }
    }

    // When the scheme of the input URL is "file", it should be interpreted as a file path.
    if discover.source.clone().starts_with("file://") {
        if let Some(path) = discover.source.clone().strip_prefix("file://") {
            return Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into());
        } else {
            return Err(anyhow::Error::msg(format!(
                "This is not a standard path or the path does not exist. Please double-check carefully. : {}",
                discover.source.clone()
            )));
        }
    }
    if discover.source.clone().starts_with("file:") {
        if let Some(path) = discover.source.clone().strip_prefix("file:") {
            return Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into());
        } else {
            return Err(anyhow::Error::msg(format!(
                "This is not a standard path or the path does not exist. Please double-check carefully. : {}",
                discover.source.clone()
            )));
        }
    }
    Err(anyhow::Error::msg(format!(
        "This is not a standard URL or the path does not exist , please check again carefully. : {}",
        discover.source.clone()
    )))
}
