use crate::discover::DiscoveredSbom;
use crate::model::{self, metadata::SourceMetadata};
use crate::retrieve::{RetrievalMetadata, RetrievedSbom};
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
use walker_common::retrieve::RetrievingDigest;
use walker_common::validate::source::Key;
use walker_common::{
    changes::{self, ChangeSource},
    fetcher::{self, DataProcessor, Fetcher, Json},
    retrieve::RetrievedDigest,
    utils::{self, openpgp::PublicKey},
    validate::source::{KeySource, KeySourceError},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpOptions {
    pub since: Option<SystemTime>,
    pub keys: Vec<model::metadata::Key>,
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

impl From<changes::Error> for HttpSourceError {
    fn from(value: changes::Error) -> Self {
        match value {
            changes::Error::Fetcher(err) => Self::Fetcher(err),
            changes::Error::Url(err) => Self::Url(err),
            changes::Error::Csv(err) => Self::Csv(err),
        }
    }
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

    async fn load_metadata(&self) -> Result<SourceMetadata, Self::Error> {
        Ok(SourceMetadata {
            keys: self.options.keys.clone(),
        })
    }

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

    async fn load_sbom(&self, discovered: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error> {
        let (signature, sha256, sha512) = try_join!(
            self.fetcher
                .fetch::<Option<String>>(format!("{url}.asc", url = discovered.url)),
            self.fetcher
                .fetch::<Option<String>>(format!("{url}.sha256", url = discovered.url)),
            self.fetcher
                .fetch::<Option<String>>(format!("{url}.sha512", url = discovered.url)),
        )?;

        let sha256 = sha256
            // take the first "word" from the line
            .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha256::new(),
            });
        let sha512 = sha512
            // take the first "word" from the line
            .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha512::new(),
            });

        let advisory = self
            .fetcher
            .fetch_processed(
                discovered.url.clone(),
                FetchingRetrievedSbom { sha256, sha512 },
            )
            .await?;

        Ok(advisory.into_retrieved(discovered, signature))
    }
}

pub struct FetchedRetrievedSbom {
    data: Bytes,
    sha256: Option<RetrievedDigest<Sha256>>,
    sha512: Option<RetrievedDigest<Sha512>>,
    metadata: RetrievalMetadata,
}

impl FetchedRetrievedSbom {
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
}

pub struct FetchingRetrievedSbom {
    pub sha256: Option<RetrievingDigest<Sha256>>,
    pub sha512: Option<RetrievingDigest<Sha512>>,
}

#[async_trait(?Send)]
impl DataProcessor for FetchingRetrievedSbom {
    type Type = FetchedRetrievedSbom;

    async fn process(&self, response: Response) -> Result<Self::Type, reqwest::Error> {
        let mut response = response.error_for_status()?;

        let mut data = BytesMut::new();
        let mut sha256 = self.sha256.clone();
        let mut sha512 = self.sha512.clone();

        while let Some(chunk) = response.chunk().await? {
            if let Some(d) = &mut sha256 {
                d.update(&chunk);
            }
            if let Some(d) = &mut sha512 {
                d.update(&chunk);
            }
            data.put(chunk);
        }

        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|s| s.to_str().ok())
            .map(ToString::to_string);

        let last_modification = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| OffsetDateTime::parse(s, &Rfc2822).ok());

        Ok(FetchedRetrievedSbom {
            data: data.freeze(),
            sha256: sha256.map(|d| d.into()),
            sha512: sha512.map(|d| d.into()),
            metadata: RetrievalMetadata {
                last_modification,
                etag,
            },
        })
    }
}

#[async_trait(?Send)]
impl KeySource for HttpSource {
    type Error = fetcher::Error;

    async fn load_public_key<'a>(
        &self,
        key_source: Key<'a>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        self.fetcher.load_public_key(key_source).await
    }
}
