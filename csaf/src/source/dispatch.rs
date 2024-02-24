use super::Source;
use crate::discover::{DiscoverContext, DiscoveredAdvisory};
use crate::model::metadata::ProviderMetadata;
use crate::retrieve::RetrievedAdvisory;
use crate::source::{FileSource, HttpSource};
use async_trait::async_trait;
use walker_common::{
    utils::openpgp::PublicKey,
    validate::source::{Key, KeySource, KeySourceError, MapSourceError},
};

/// A common source type, dispatching to the known implementations.
///
/// This helps to create implementations which don't need to know the exact type. Unfortunately we
/// cannot just "box" this, as the [`Source`] needs to implement [`Clone`], which requires [`Sized`],
/// which prevents us from using `dyn` ("cannot be made into an object").
///
/// There may be a better way around this, feel free to send a PR ;-)
#[derive(Clone)]
pub enum DispatchSource {
    File(FileSource),
    Http(HttpSource),
}

impl From<FileSource> for DispatchSource {
    fn from(value: FileSource) -> Self {
        Self::File(value)
    }
}

impl From<HttpSource> for DispatchSource {
    fn from(value: HttpSource) -> Self {
        Self::Http(value)
    }
}

#[async_trait(?Send)]
impl Source for DispatchSource {
    type Error = anyhow::Error;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        match self {
            Self::File(source) => source.load_metadata().await,
            Self::Http(source) => source.load_metadata().await.map_err(|err| err.into()),
        }
    }

    async fn load_index(
        &self,
        context: DiscoverContext,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        match self {
            Self::File(source) => source.load_index(context).await,
            Self::Http(source) => source.load_index(context).await.map_err(|err| err.into()),
        }
    }

    async fn load_advisory(
        &self,
        advisory: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error> {
        match self {
            Self::File(source) => source.load_advisory(advisory).await,
            Self::Http(source) => source
                .load_advisory(advisory)
                .await
                .map_err(|err| err.into()),
        }
    }
}

#[async_trait(?Send)]
impl KeySource for DispatchSource {
    type Error = anyhow::Error;

    async fn load_public_key<'a>(
        &self,
        key: Key<'a>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        match self {
            Self::File(source) => source.load_public_key(key).await,
            Self::Http(source) => source
                .load_public_key(key)
                .await
                .map_source(|err| err.into()),
        }
    }
}
