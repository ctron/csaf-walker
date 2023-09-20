//! Sources

mod dispatch;
mod file;
mod http;

pub use dispatch::*;
pub use file::*;
pub use http::*;

use crate::discover::DiscoveredAdvisory;
use crate::model::metadata::{Distribution, Key, ProviderMetadata};
use crate::retrieve::RetrievedAdvisory;
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use walker_common::utils::{self, openpgp::PublicKey};

/// A source of CSAF documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error>;
    async fn load_index(
        &self,
        distribution: &Distribution,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error>;
    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum KeySourceError<SE: Display + Debug> {
    #[error("Key source error: {0}")]
    Source(SE),
    #[error("Key error: {0}")]
    OpenPgp(utils::openpgp::Error),
}

pub trait MapSourceError<T, SE> {
    fn map_source<F, TE>(self, f: F) -> Result<T, KeySourceError<TE>>
    where
        F: FnOnce(SE) -> TE,
        TE: Display + Debug;
}

impl<T, SE: Display + Debug> MapSourceError<T, SE> for Result<T, KeySourceError<SE>> {
    fn map_source<F, TE>(self, f: F) -> Result<T, KeySourceError<TE>>
    where
        F: FnOnce(SE) -> TE,
        TE: Display + Debug,
    {
        self.map_err(|err| err.map_source(f))
    }
}

impl<SE: Display + Debug> KeySourceError<SE> {
    pub fn map_source<F, E>(self, f: F) -> KeySourceError<E>
    where
        F: FnOnce(SE) -> E,
        E: Display + Debug,
    {
        match self {
            Self::Source(err) => KeySourceError::Source(f(err)),
            Self::OpenPgp(err) => KeySourceError::OpenPgp(err),
        }
    }
}

/// A source of CSAF public keys
#[async_trait(?Send)]
pub trait KeySource: Clone {
    type Error: Display + Debug;

    async fn load_public_key(&self, key: &Key) -> Result<PublicKey, KeySourceError<Self::Error>>;
}
