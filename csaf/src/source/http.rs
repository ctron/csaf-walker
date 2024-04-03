use crate::metadata_retriever::{DetectionType, MetadataRetriever};
use crate::{
    discover::{DiscoveredAdvisory, DistributionContext},
    model::metadata::ProviderMetadata,
    retrieve::RetrievedAdvisory,
    rolie::{RolieSource, SourceFile},
    source::Source,
};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use futures::try_join;
use reqwest::Response;
use sha2::{Sha256, Sha512};
use std::sync::Arc;
use std::time::SystemTime;
use time::{format_description::well_known::Rfc2822, OffsetDateTime};
use url::{ParseError, Url};
use walker_common::{
    changes::{self, ChangeEntry, ChangeSource},
    fetcher::{self, DataProcessor, Fetcher},
    retrieve::{RetrievalMetadata, RetrievedDigest, RetrievingDigest},
    utils::openpgp::PublicKey,
    validate::source::{Key, KeySource, KeySourceError},
};

pub const WELL_KNOWN_METADATA: &str = ".well-known/csaf/provider-metadata.json";

#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpOptions {
    pub since: Option<SystemTime>,
}

impl HttpOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

#[derive(Clone)]
pub struct HttpSource {
    fetcher: Fetcher,
    url: String,
    options: HttpOptions,
}

impl HttpSource {
    pub fn new(url: String, fetcher: Fetcher, options: HttpOptions) -> Self {
        Self {
            url,
            fetcher,
            options,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpSourceError {
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("securityTxt ParseError error: {0}")]
    SecurityTextError(#[from] sectxtlib::ParseError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("The provider metadata obtained from this URL is 'None': {0}")]
    EmptyProviderMetadata(String),
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

#[async_trait(?Send)]
impl Source for HttpSource {
    type Error = HttpSourceError;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        let metadata_retriever = MetadataRetriever {
            base_url: self.url.clone(),
            fetcher: self.fetcher.clone(),
        };

        if self.url.contains(WELL_KNOWN_METADATA) {
            if let Some(metadata) = metadata_retriever
                .fetch_metadata_from_url(Url::parse(self.url.clone().as_str())?)
                .await?
            {
                return Ok(metadata.into_inner());
            } else {
                return Err(Self::Error::EmptyProviderMetadata(self.url.clone()));
            }
        }

        match metadata_retriever.retrieve().await? {
            DetectionType::WellKnowPath(provider_metadata) => {
                log::info!("Finally get provider metadata from fully provided discovery URL");
                Ok(provider_metadata)
            }
            DetectionType::DnsPath(provider_metadata) => {
                log::info!("Finally get provider metadata from dns path of provided discovery URL");
                Ok(provider_metadata)
            }
            DetectionType::SecurityTextPath(provider_metadata) => {
                log::info!(
                    "Finally get provider metadata from sercurity text of provided discovery URL"
                );
                Ok(provider_metadata)
            }
        }
    }

    async fn load_index(
        &self,
        context: DistributionContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        let discover_context = Arc::new(context);

        // filter out advisories based on since, but only if we can be sure
        let since_filter = |advisory: &Result<_, _>| match (advisory, &self.options.since) {
            (
                Ok(DiscoveredAdvisory {
                    url: _,
                    context: _,
                    modified,
                }),
                Some(since),
            ) => modified >= since,
            _ => true,
        };

        match discover_context.as_ref() {
            DistributionContext::Directory(base) => {
                let has_slash = base.to_string().ends_with('/');

                let join_url = |mut s: &str| {
                    if has_slash && s.ends_with('/') {
                        s = &s[1..];
                    }
                    Url::parse(&format!("{}{s}", base))
                };

                let changes = ChangeSource::retrieve(&self.fetcher, &base.clone()).await?;

                Ok(changes
                    .entries
                    .into_iter()
                    .map(|ChangeEntry { file, timestamp }| {
                        let modified = timestamp.into();
                        let url = join_url(&file)?;

                        Ok::<_, ParseError>(DiscoveredAdvisory {
                            context: discover_context.clone(),
                            url,
                            modified,
                        })
                    })
                    .filter(since_filter)
                    .collect::<Result<_, _>>()?)
            }

            DistributionContext::Feed(feed) => {
                let source_files = RolieSource::retrieve(&self.fetcher, feed.clone()).await?;
                Ok(source_files
                    .files
                    .into_iter()
                    .map(|SourceFile { file, timestamp }| {
                        let modified = timestamp.into();
                        let url = Url::parse(&file)?;

                        Ok::<_, ParseError>(DiscoveredAdvisory {
                            context: discover_context.clone(),
                            url,
                            modified,
                        })
                    })
                    .filter(since_filter)
                    .collect::<Result<_, _>>()?)
            }
        }
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

    async fn load_public_key<'a>(
        &self,
        key_source: Key<'a>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        self.fetcher.load_public_key(key_source).await
    }
}
