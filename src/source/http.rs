use crate::discover::DiscoveredAdvisory;
use crate::fetcher::{DataProcessor, Fetcher, Json};
use crate::model::metadata::{Distribution, Key, ProviderMetadata};
use crate::retrieve::{RetrievalMetadata, RetrievedAdvisory, RetrievedDigest, RetrievingDigest};
use crate::source::{KeySource, KeySourceError, Source};
use crate::utils::openpgp::PublicKey;
use crate::{fetcher, utils};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use futures::try_join;
use reqwest::Response;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use std::time::SystemTime;
use time::format_description::well_known::Rfc2822;
use time::OffsetDateTime;
use url::{ParseError, Url};

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

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        Ok(self
            .fetcher
            .fetch::<Json<ProviderMetadata>>(self.url.clone())
            .await?
            .into_inner())
    }

    async fn load_index(
        &self,
        distribution: &Distribution,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        let base = distribution.directory_url.to_string();
        let has_slash = base.ends_with('/');

        let join_url = |mut s: &str| {
            if has_slash && s.ends_with('/') {
                s = &s[1..];
            }
            Url::parse(&format!("{}{s}", base))
        };

        let changes = ChangeSource::retrieve(&self.fetcher, &distribution.directory_url).await?;

        Ok(self
            .fetcher
            .fetch::<String>(distribution.directory_url.join("index.txt")?)
            .await?
            .lines()
            .map(|line| {
                let modified = changes.modified(line);
                let url = join_url(line)?;

                Ok::<_, ParseError>(DiscoveredAdvisory { url, modified })
            })
            // filter out advisories based in since, but only if we can be sure
            .filter(|advisory| match (advisory, &self.options.since) {
                (
                    Ok(DiscoveredAdvisory {
                        url: _,
                        modified: Some(modified),
                    }),
                    Some(since),
                ) => modified >= since,
                _ => true,
            })
            .collect::<Result<_, _>>()?)
    }

    async fn load_advisory(
        &self,
        discovered: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error> {
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
                FetchingRetrievedAdvisory { sha256, sha512 },
            )
            .await?;

        Ok(advisory.into_retrieved(discovered, signature))
    }
}

pub struct FetchedRetrievedAdvisory {
    data: Bytes,
    sha256: Option<RetrievedDigest<Sha256>>,
    sha512: Option<RetrievedDigest<Sha512>>,
    metadata: RetrievalMetadata,
}

impl FetchedRetrievedAdvisory {
    fn into_retrieved(
        self,
        discovered: DiscoveredAdvisory,
        signature: Option<String>,
    ) -> RetrievedAdvisory {
        RetrievedAdvisory {
            discovered,
            data: self.data,
            signature,
            sha256: self.sha256,
            sha512: self.sha512,
            metadata: self.metadata,
        }
    }
}

pub struct FetchingRetrievedAdvisory {
    pub sha256: Option<RetrievingDigest<Sha256>>,
    pub sha512: Option<RetrievingDigest<Sha512>>,
}

#[async_trait(?Send)]
impl DataProcessor for FetchingRetrievedAdvisory {
    type Type = FetchedRetrievedAdvisory;

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

        Ok(FetchedRetrievedAdvisory {
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

    async fn load_public_key(
        &self,
        key_source: &Key,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        let bytes = self
            .fetcher
            .fetch::<Bytes>(key_source.url.clone())
            .await
            .map_err(KeySourceError::Source)?;

        utils::openpgp::validate_keys(bytes, &key_source.fingerprint)
            .map_err(KeySourceError::OpenPgp)
    }
}

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
