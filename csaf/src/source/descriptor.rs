use crate::{
    discover::DiscoverConfig,
    metadata::MetadataRetriever,
    source::{DispatchSource, FileOptions, FileSource, HttpOptions, HttpSource},
};
use anyhow::bail;
use fluent_uri::Uri;
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;
use walker_common::fetcher::{Fetcher, FetcherOptions};

/// A descriptor of the source.
#[derive(Clone, Debug)]
pub enum SourceDescriptor {
    /// A local file source
    File(PathBuf),
    /// A remote URL source, pointing to the `provider-metadata.json`
    Url(Url),
    /// A source discovered by the lookup process, given the domain.
    Lookup(String),
}

impl FromStr for SourceDescriptor {
    type Err = anyhow::Error;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        match Uri::parse(source) {
            Ok(uri) => match uri.scheme().map(|s| s.as_str()) {
                Some("https") => Ok(SourceDescriptor::Url(Url::parse(source)?)),
                Some("file") => Ok(SourceDescriptor::File(PathBuf::from(uri.path().as_str()))),
                Some(other) => bail!("URLs with scheme '{other}' are not supported"),
                None => Ok(SourceDescriptor::Lookup(source.to_string())),
            },
            Err(err) => {
                log::debug!("Failed to handle source as URL: {err}");
                Ok(SourceDescriptor::Lookup(source.to_string()))
            }
        }
    }
}

impl SourceDescriptor {
    /// Parse a string into a source descriptor.
    pub fn parse(source: impl AsRef<str>) -> anyhow::Result<Self> {
        Self::from_str(source.as_ref())
    }

    /// If possible, turn this into a source.
    pub async fn into_source(
        self,
        discover: DiscoverConfig,
        fetcher: FetcherOptions,
    ) -> anyhow::Result<DispatchSource> {
        match self {
            Self::File(path) => {
                Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into())
            }
            Self::Url(url) => Ok(HttpSource::new(
                url,
                Fetcher::new(fetcher).await?,
                HttpOptions::new().since(discover.since),
            )
            .into()),
            Self::Lookup(source) => {
                let fetcher = Fetcher::new(fetcher).await?;
                Ok(HttpSource::new(
                    MetadataRetriever::new(source),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into())
            }
        }
    }
}
