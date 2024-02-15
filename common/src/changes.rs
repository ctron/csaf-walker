//! Changes based on the `changes.csv` file.

use crate::fetcher::{self, Fetcher};
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

/// An entry when a resource was last changed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct ChangeEntry {
    /// The relative file name
    pub file: String,
    /// The timestamp of the last change
    #[serde(with = "time::serde::iso8601")]
    pub timestamp: OffsetDateTime,
}

/// State of a `changes.csv` file.
pub struct ChangeSource {
    pub entries: Vec<ChangeEntry>,
}

impl ChangeSource {
    /// Retrieve a file using a [`Fetcher`].
    pub async fn retrieve(fetcher: &Fetcher, base_url: &Url) -> Result<Self, Error> {
        let changes = fetcher
            .fetch::<String>(base_url.join("changes.csv")?)
            .await?;

        log::info!("Found 'changes.csv', processing data");

        let reader = csv::ReaderBuilder::new()
            .delimiter(b',')
            .has_headers(false)
            .from_reader(changes.as_bytes());

        let entries = reader
            .into_deserialize::<ChangeEntry>()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { entries })
    }
}
