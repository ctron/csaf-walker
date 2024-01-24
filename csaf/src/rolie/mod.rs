mod roliefeed;

use crate::rolie::roliefeed::RolieFeed;
use crate::source::HttpSourceError;
use async_trait::async_trait;
use time::OffsetDateTime;
use url::{ParseError, Url};
use walker_common::fetcher;
use walker_common::fetcher::Fetcher;

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
pub struct SourceFiles {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<SourceFile>,
}
#[async_trait(?Send)]
pub trait RolieRetrievable {
    async fn retrieve_rolie(fetcher: &Fetcher, base_url: Url) -> Result<Self, Error>
    where
        Self: Sized + Send;
}

#[async_trait(?Send)]
impl RolieRetrievable for SourceFiles {
    async fn retrieve_rolie(fetcher: &Fetcher, base_url: Url) -> Result<Self, Error>
    where
        Self: Sized + Send,
    {
        let mut files = vec![];
        let changes = fetcher.fetch::<String>(base_url).await?;
        let result: RolieFeed = serde_json::from_str::<RolieFeed>(&changes)?;
        for url in result.feed.entry {
            for link in url.link {
                files.push(SourceFile {
                    file: link.href.to_string(),
                    timestamp: url.updated,
                })
            }
        }
        log::info!("list all entry size is  {:?}", files.len());
        Ok(Self { files })
    }
}
