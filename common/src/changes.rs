use crate::fetcher::{self, Fetcher};
use std::collections::HashMap;
use std::time::SystemTime;
use time::OffsetDateTime;
use url::{ParseError, Url};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
struct ChangeEntry {
    file: String,
    #[serde(with = "time::serde::iso8601")]
    timestamp: OffsetDateTime,
}

pub struct ChangeSource {
    map: HashMap<String, SystemTime>,
}

impl ChangeSource {
    pub fn modified(&self, file: &str) -> Option<SystemTime> {
        self.map.get(file).copied()
    }

    pub async fn retrieve(fetcher: &Fetcher, base_url: &Url) -> Result<Self, Error> {
        let changes = fetcher
            .fetch::<Option<String>>(base_url.join("changes.csv")?)
            .await?;

        log::info!("Found 'changes.txt', loading data");

        let map = if let Some(changes) = changes {
            let reader = csv::ReaderBuilder::new()
                .delimiter(b',')
                .has_headers(false)
                .from_reader(changes.as_bytes());

            reader
                .into_deserialize::<ChangeEntry>()
                .map(|entry| entry.map(|entry| (entry.file, entry.timestamp.into())))
                .collect::<Result<HashMap<_, _>, _>>()?
        } else {
            HashMap::new()
        };

        Ok(Self { map })
    }
}
