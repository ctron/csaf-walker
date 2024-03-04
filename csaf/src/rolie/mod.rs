mod roliefeed;

pub use roliefeed::*;

use crate::source::HttpSourceError;
use time::OffsetDateTime;
use url::{ParseError, Url};
use walker_common::fetcher::Json;
use walker_common::{fetcher, fetcher::Fetcher};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<Error> for HttpSourceError {
    fn from(value: Error) -> Self {
        match value {
            Error::Fetcher(err) => Self::Fetcher(err),
            Error::Url(err) => Self::Url(err),
            Error::Json(err) => Self::Json(err),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct SourceFile {
    /// The relative file name
    pub file: String,
    /// The timestamp of the last change
    #[serde(with = "time::serde::iso8601")]
    pub timestamp: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RolieSource {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<SourceFile>,
}

impl RolieSource {
    pub async fn retrieve(fetcher: &Fetcher, base_url: Url) -> Result<Self, Error> {
        let mut files = vec![];
        let Json(result) = fetcher.fetch::<Json<RolieFeed>>(base_url).await?;
        for url in result.feed.entry {
            for link in url.link {
                files.push(SourceFile {
                    file: link.href,
                    timestamp: url.updated,
                })
            }
        }

        log::debug!("found {:?} files", files.len());

        Ok(Self { files })
    }
}
