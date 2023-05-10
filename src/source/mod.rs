//! Source abstractions

mod http;

pub use http::*;
use std::fmt::{Debug, Display};

use crate::discover::DiscoveredAdvisory;
use crate::model::metadata::{Distribution, Key, ProviderMetadata};
use crate::retrieve::RetrievedAdvisory;
use crate::utils;
use crate::utils::openpgp::PublicKey;
use async_trait::async_trait;
use url::Url;

/// A source of CSAF documents
#[async_trait(?Send)]
pub trait Source: Clone {
    type Error: Display + Debug;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error>;
    async fn load_index(&self, distribution: &Distribution) -> Result<Vec<Url>, Self::Error>;
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

/// A source of CSAF public keys
#[async_trait(?Send)]
pub trait KeySource: Clone {
    type Error: Display + Debug;

    async fn load_public_key(&self, key: &Key) -> Result<PublicKey, KeySourceError<Self::Error>>;
}
