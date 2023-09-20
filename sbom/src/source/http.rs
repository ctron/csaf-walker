use crate::discover::DiscoveredSbom;
use crate::source::Source;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use futures::try_join;
use reqwest::Response;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::fmt::format;
use std::time::SystemTime;
use time::{format_description::well_known::Rfc2822, OffsetDateTime};
use url::{ParseError, Url};
use walker_common::retrieve::RetrievedDigest;
use walker_common::{
    fetcher::{self, DataProcessor, Fetcher, Json},
    utils::{self, openpgp::PublicKey},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpOptions {
    pub since: Option<SystemTime>,
}

#[derive(Clone)]
pub struct HttpSource {
    pub fetcher: Fetcher,
    pub url: Url,
    pub options: HttpOptions,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpSourceError {
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

#[async_trait(?Send)]
impl Source for HttpSource {
    type Error = HttpSourceError;

    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error> {
        let base = match self.url.path().ends_with("/") {
            true => self.url.clone(),
            false => Url::parse(&format!("{}/", self.url))?,
        };

        let changes = ChangeSource::retrieve(&self.fetcher, &base).await?;

        Ok(self
            .fetcher
            .fetch::<String>(base.join("index.txt")?)
            .await?
            .lines()
            .map(|line| {
                let modified = changes.modified(line);
                let url = base.join(line)?;

                Ok::<_, ParseError>(DiscoveredSbom { url, modified })
            })
            // filter out advisories based in since, but only if we can be sure
            .filter(|advisory| match (advisory, &self.options.since) {
                (
                    Ok(DiscoveredSbom {
                        url: _,
                        modified: Some(modified),
                    }),
                    Some(since),
                ) => modified >= since,
                _ => true,
            })
            .collect::<Result<_, _>>()?)
    }
}

/*
pub struct FetchedRetrievedAdvisory {
    data: Bytes,
    sha256: Option<RetrievedDigest<Sha256>>,
    sha512: Option<RetrievedDigest<Sha512>>,
}

impl FetchedRetrievedAdvisory {
    fn into_retrieved(
        self,
        discovered: DiscoveredSbom,
        signature: Option<String>,
    ) -> RetrievedSbom {
        RetrievedSbom {
            discovered,
            data: self.data,
            signature,
            sha256: self.sha256,
            sha512: self.sha512,
            metadata: self.metadata,
        }
    }
}*/

pub struct ChangeSource {
    map: HashMap<String, SystemTime>,
}

impl ChangeSource {
    pub fn modified(&self, file: &str) -> Option<SystemTime> {
        self.map.get(file).copied()
    }

    pub async fn retrieve(fetcher: &Fetcher, base_url: &Url) -> Result<Self, HttpSourceError> {
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
