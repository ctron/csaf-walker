mod roliefeed;

use crate::rolie::roliefeed::RolieFeed;
use async_trait::async_trait;
use url::Url;
use walker_common::changes::{ChangeEntry, ChangeSource, Error};
use walker_common::fetcher::Fetcher;

#[async_trait(?Send)]
pub trait RolieRetrievable {
    async fn retrieve_rolie(fetcher: &Fetcher, base_url: Url) -> Result<Self, Error>
    where
        Self: Sized + Send;
}

#[async_trait(?Send)]
impl RolieRetrievable for ChangeSource {
    async fn retrieve_rolie(fetcher: &Fetcher, url: Url) -> Result<Self, Error> {
        let mut entries = vec![];
        let changes = fetcher.fetch::<String>(url).await?;
        let result: Result<RolieFeed, serde_json::Error> =
            serde_json::from_str::<RolieFeed>(&changes);
        match result {
            Ok(feed) => {
                for url in feed.feed.entry {
                    for link in url.link {
                        let href = &link.href;
                        if href.ends_with(".json") {
                            entries.push(ChangeEntry {
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
        log::info!("list all entry size is  {:?}", entries.len());
        Ok(Self { entries })
    }
}
