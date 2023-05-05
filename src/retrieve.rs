//! Retrieval

use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::model::metadata::ProviderMetadata;
use crate::utils::{fetch::fetch_string_optional, hex::Hex};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use digest::{Digest, Output};
use reqwest::StatusCode;
use sha2::{Sha256, Sha512};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
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
    client: reqwest::Client,
}

impl<V> RetrievingVisitor<V>
where
    V: RetrievedVisitor,
{
    pub fn new(client: reqwest::Client, visitor: V) -> Self {
        Self { visitor, client }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: std::fmt::Display + Debug,
{
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
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
            fetch_string_optional(&self.client, format!("{url}.asc", url = discovered.url)),
            fetch_string_optional(&self.client, format!("{url}.sha256", url = discovered.url)),
            fetch_string_optional(&self.client, format!("{url}.sha512", url = discovered.url)),
        )?;

        let mut sha256 = sha256
            // take the first "word" from the line
            .and_then(|expected| expected.split(" ").next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha256::new(),
            });
        let mut sha512 = sha512
            // take the first "word" from the line
            .and_then(|expected| expected.split(" ").next().map(ToString::to_string))
            .map(|expected| RetrievingDigest {
                expected,
                current: Sha512::new(),
            });

        let mut response = self.client.get(discovered.url.clone()).send().await?;

        if !response.status().is_success() {
            self.visitor
                .visit_advisory(
                    context,
                    Err(RetrievalError::InvalidResponse(response.status())),
                )
                .await
                .map_err(Error::Visitor)?;
            return Ok(());
        }

        let mut data = BytesMut::new();

        while let Some(chunk) = response.chunk().await? {
            if let Some(d) = &mut sha256 {
                d.update(&chunk);
            }
            if let Some(d) = &mut sha512 {
                d.update(&chunk);
            }
            data.put(chunk);
        }

        let advisory = RetrievedAdvisory {
            discovered,
            data: data.freeze(),
            signature,
            sha256: sha256.map(|d| d.into()),
            sha512: sha512.map(|d| d.into()),
        };

        self.visitor
            .visit_advisory(context, Ok(advisory))
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}
