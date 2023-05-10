//! Retrieval

use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::source::{KeySource, KeySourceError, Source};
use crate::utils::hex::Hex;
use crate::utils::openpgp::PublicKey;
use async_trait::async_trait;
use bytes::Bytes;
use digest::{Digest, Output};
use reqwest::StatusCode;
use sha2::{Sha256, Sha512};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use time::OffsetDateTime;
use url::Url;

/// A retrieved (but unverified) advisory
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

/// Metadata of the retrieval process.
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

/// The retrieved digest
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
pub struct RetrievingDigest<D: Digest> {
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
    #[error("Invalid response retrieving: {code}")]
    InvalidResponse {
        code: StatusCode,
        discovered: DiscoveredAdvisory,
    },
}

impl RetrievalError {
    pub fn url(&self) -> &Url {
        match self {
            Self::InvalidResponse { discovered, .. } => &discovered.url,
        }
    }
}

pub struct RetrievalContext<'c> {
    pub discovered: &'c DiscoveredContext<'c>,
    pub keys: &'c Vec<PublicKey>,
}

impl<'c> Deref for RetrievalContext<'c> {
    type Target = DiscoveredContext<'c>;

    fn deref(&self) -> &Self::Target {
        &self.discovered
    }
}

#[async_trait(?Send)]
pub trait RetrievedVisitor {
    type Error: std::fmt::Display + Debug;
    type Context;

    async fn visit_context(&self, context: &RetrievalContext)
        -> Result<Self::Context, Self::Error>;

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
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
        _context: &RetrievalContext,
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

pub struct RetrievingVisitor<V: RetrievedVisitor, S: Source + KeySource> {
    visitor: V,
    source: S,
}

impl<V, S> RetrievingVisitor<V, S>
where
    V: RetrievedVisitor,
    S: Source + KeySource,
{
    pub fn new(source: S, visitor: V) -> Self {
        Self { visitor, source }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE, KSE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
    KSE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error("Key source error: {0}")]
    KeySource(KeySourceError<KSE>),
    #[error(transparent)]
    Visitor(VE),
}

#[async_trait(?Send)]
impl<V, S> DiscoveredVisitor for RetrievingVisitor<V, S>
where
    V: RetrievedVisitor,
    S: Source + KeySource,
{
    type Error = Error<V::Error, <S as Source>::Error, <S as KeySource>::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        let mut keys = Vec::with_capacity(context.metadata.public_openpgp_keys.len());

        for key in &context.metadata.public_openpgp_keys {
            keys.push(
                self.source
                    .load_public_key(key)
                    .await
                    .map_err(Error::KeySource)?,
            );
        }

        log::info!("Loaded {} public keys", keys.len());
        if log::log_enabled!(log::Level::Debug) {
            for key in keys.iter().flat_map(|k| &k.certs) {
                log::debug!("   {}", key.key_handle());
                for id in key.userids() {
                    log::debug!("     {}", String::from_utf8_lossy(id.value()));
                }
            }
        }

        self.visitor
            .visit_context(&RetrievalContext {
                discovered: &context,
                keys: &keys,
            })
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        discovered: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        let advisory = self
            .source
            .load_advisory(discovered)
            .await
            .map_err(Error::Source)?;

        self.visitor
            .visit_advisory(context, Ok(advisory))
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}
