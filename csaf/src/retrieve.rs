//! Retrieval

use crate::{
    discover::{AsDiscovered, DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor},
    source::Source,
};
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::StatusCode;
use sha2::{Sha256, Sha512};
use std::fmt::Debug;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use url::Url;
use walker_common::{
    retrieve::{RetrievalMetadata, RetrievedDigest},
    utils::{openpgp::PublicKey, url::Urlify},
    validate::source::{KeySource, KeySourceError},
};

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

impl Urlify for RetrievedAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.discovered.relative_base_and_url()
    }
}

/// Get a document as [`RetrievedAdvisory`]
pub trait AsRetrieved: Debug {
    fn as_retrieved(&self) -> &RetrievedAdvisory;
}

impl AsDiscovered for RetrievedAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        &self.discovered
    }
}

impl AsRetrieved for RetrievedAdvisory {
    fn as_retrieved(&self) -> &RetrievedAdvisory {
        self
    }
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

#[derive(Clone, Debug, thiserror::Error)]
pub enum RetrievalError {
    #[error("Invalid response retrieving: {code}")]
    InvalidResponse {
        code: StatusCode,
        discovered: DiscoveredAdvisory,
    },
}

impl RetrievalError {
    pub fn discovered(&self) -> &DiscoveredAdvisory {
        match self {
            Self::InvalidResponse { discovered, .. } => discovered,
        }
    }
}

impl Urlify for RetrievalError {
    fn url(&self) -> &Url {
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
        self.discovered
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
                    .load_public_key(key.into())
                    .await
                    .map_err(Error::KeySource)?,
            );
        }

        log::info!(
            "Loaded {} public key{}",
            keys.len(),
            (keys.len() != 1).then_some("s").unwrap_or_default()
        );
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
                discovered: context,
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
