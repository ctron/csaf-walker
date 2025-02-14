use crate::discover::DiscoveredSbom;
use crate::model::metadata::SourceMetadata;
use crate::retrieve::RetrievedSbom;
use crate::source::{FileSource, HttpSource, HttpSourceError, Source};
use walker_common::{
    utils::openpgp::PublicKey,
    validate::source::{Key, KeySource, KeySourceError, MapSourceError},
};

/// A common source type, dispatching to the known implementations.
///
/// This helps creating implementations which don't need to know the exact type. Unfortunately, we
/// cannot just "box" this, as the [`Source`] needs to implement [`Clone`], which requires [`Sized`],
/// which prevents us from using `dyn` ("cannot be made into an object").
///
/// There may be a better way around this, feel free to send a PR ;-)
#[derive(Clone, Debug)]
pub enum DispatchSource {
    Http(HttpSource),
    File(FileSource),
}

impl From<HttpSource> for DispatchSource {
    fn from(value: HttpSource) -> Self {
        Self::Http(value)
    }
}

impl From<FileSource> for DispatchSource {
    fn from(value: FileSource) -> Self {
        Self::File(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchSourceError {
    #[error(transparent)]
    File(anyhow::Error),
    #[error(transparent)]
    Http(HttpSourceError),
}

impl walker_common::source::Source for DispatchSource {
    type Error = DispatchSourceError;
    type Retrieved = RetrievedSbom;
}

impl Source for DispatchSource {
    async fn load_metadata(&self) -> Result<SourceMetadata, Self::Error> {
        match self {
            Self::File(source) => Ok(source
                .load_metadata()
                .await
                .map_err(DispatchSourceError::File)?),
            Self::Http(source) => Ok(source
                .load_metadata()
                .await
                .map_err(DispatchSourceError::Http)?),
        }
    }

    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error> {
        match self {
            Self::File(source) => Ok(source
                .load_index()
                .await
                .map_err(DispatchSourceError::File)?),
            Self::Http(source) => Ok(source
                .load_index()
                .await
                .map_err(DispatchSourceError::Http)?),
        }
    }

    async fn load_sbom(&self, sbom: DiscoveredSbom) -> Result<RetrievedSbom, Self::Error> {
        match self {
            Self::File(source) => Ok(source
                .load_sbom(sbom)
                .await
                .map_err(DispatchSourceError::File)?),
            Self::Http(source) => Ok(source
                .load_sbom(sbom)
                .await
                .map_err(DispatchSourceError::Http)?),
        }
    }
}

impl KeySource for DispatchSource {
    type Error = anyhow::Error;

    async fn load_public_key(
        &self,
        key: Key<'_>,
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
