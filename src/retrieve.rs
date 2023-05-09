//! Retrieval

use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::fetcher;
use crate::fetcher::{DataProcessor, Fetcher};
use crate::model::metadata::ProviderMetadata;
use crate::utils::hex::Hex;
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use digest::{Digest, Output};
use reqwest::{Response, StatusCode};
use sha2::{Sha256, Sha512};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use time::{format_description::well_known::Rfc2822, OffsetDateTime};
use tokio::try_join;

#[derive(Clone, Debug)]
pub struct RetrievedAdvisory {
    /// The discovered advisory
    pub discovered: DiscoveredAdvisory,

    /// The advisory data
    pub data: Bytes,
    /// Signature data
    pub signature: Option<String>,

    /// SHA-256 digest
    pub sha256: Option<RetrievedDigest<Sha256>>,
    /// SHA-512 digest
    pub sha512: Option<RetrievedDigest<Sha512>>,

    /// Metadata from the retrieval process
    pub metadata: RetrievalMetadata,
}

#[derive(Clone, Debug)]
pub struct RetrievalMetadata {
    /// Last known modification time
    pub last_modification: Option<OffsetDateTime>,
    /// ETag
    pub etag: Option<String>,
}

impl Deref for RetrievedAdvisory {
    type Target = DiscoveredAdvisory;

    fn deref(&self) -> &Self::Target {
        &self.discovered
    }
}

impl DerefMut for RetrievedAdvisory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.discovered
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RetrievedDigest<D: Digest> {
    /// The expected digest, as read from the remote source
    pub expected: String,
    /// The actual digest, as calculated from reading the content
    pub actual: Output<D>,
}

impl<D: Digest> RetrievedDigest<D> {
    pub fn validate(&self) -> Result<(), (&str, String)> {
        let actual = Hex(&self.actual).to_lower();
        if self.expected == actual {
            Ok(())
        } else {
            Err((&self.expected, actual))
        }
    }
}

impl<D: Digest> Debug for RetrievedDigest<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetrievedDigest")
            .field("expected", &self.expected)
            .field("actual", &Hex(&self.actual))
            .finish()
    }
}

/// Building a digest while retrieving.
#[derive(Clone)]
struct RetrievingDigest<D: Digest> {
    pub expected: String,
    pub current: D,
}

impl<D> Deref for RetrievingDigest<D>
where
    D: Digest,
{
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.current
    }
}

impl<D> DerefMut for RetrievingDigest<D>
where
    D: Digest,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

impl<D> From<RetrievingDigest<D>> for RetrievedDigest<D>
where
    D: Digest,
{
    fn from(value: RetrievingDigest<D>) -> Self {
        Self {
            expected: value.expected,
            actual: value.current.finalize(),
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum RetrievalError {
    #[error("Invalid response retrieving: {0}")]
    InvalidResponse(StatusCode),
}

#[async_trait(?Send)]
pub trait RetrievedVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    async fn visit_context(
        &self,
        metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error>;

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        outcome: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
impl<F, E, Fut> RetrievedVisitor for F
where
    F: Fn(Result<RetrievedAdvisory, RetrievalError>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: std::fmt::Display + Debug,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        outcome: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self(outcome).await
    }
}

pub struct RetrievingVisitor<V: RetrievedVisitor> {
    visitor: V,
    fetcher: Fetcher,
}

impl<V> RetrievingVisitor<V>
where
    V: RetrievedVisitor,
{
    pub fn new(fetcher: Fetcher, visitor: V) -> Self {
        Self { visitor, fetcher }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: std::fmt::Display + Debug,
{
    #[error("Fetch error: {0}")]
    Fetch(#[from] fetcher::Error),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

#[async_trait(?Send)]
impl<V> DiscoveredVisitor for RetrievingVisitor<V>
where
    V: RetrievedVisitor,
{
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(metadata)
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        discovered: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
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

        self.visitor
            .visit_advisory(context, Ok(advisory.into_retrieved(discovered, signature)))
            .await
            .map_err(Error::Visitor)?;

        Ok(())
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
    sha256: Option<RetrievingDigest<Sha256>>,
    sha512: Option<RetrievingDigest<Sha512>>,
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

#[cfg(test)]
mod test {
    use time::format_description::well_known::Rfc2822;
    use time::OffsetDateTime;

    #[test]
    fn test_parse_date() {
        assert_eq!(
            OffsetDateTime::parse("Thu, 09 Mar 2023 19:46:10 GMT", &Rfc2822).ok(),
            OffsetDateTime::from_unix_timestamp(23).ok()
        );
    }
}
