mod roliefeed;

use crate::rolie::roliefeed::RolieFeed;
use async_trait::async_trait;
use time::OffsetDateTime;
use url::Url;
use walker_common::changes::Error;
use walker_common::fetcher::Fetcher;

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
        let result: Result<RolieFeed, serde_json::Error> =
            serde_json::from_str::<RolieFeed>(&changes);
        match result {
            Ok(feed) => {
                for url in feed.feed.entry {
                    for link in url.link {
                        let href = &link.href;
                        if href.ends_with(".json") {
                            files.push(SourceFile {
                                file: link.href.to_string(),
                                timestamp: url.updated,
                            })
                        }
                    }
                }
            }
            Err(e) => {
                log::warn!("parse Failed to parse JSON: {}", e)
            }
        }
        log::info!("list all entry size is  {:?}", files.len());
        Ok(Self { files })
    }
}
