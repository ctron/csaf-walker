use super::*;
use crate::sbom::{
    discover::DiscoveredSbom,
    retrieve::{RetrievalContext, RetrievalError, RetrievedSbom, RetrievedVisitor},
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError},
};
use reqwest::header;

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedSbomError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

#[async_trait(?Send)]
impl RetrievedVisitor for SendVisitor {
    type Error = SendRetrievedSbomError;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.send_sbom(result?).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendValidatedSbomError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[async_trait(?Send)]
impl ValidatedVisitor for SendVisitor {
    type Error = SendValidatedSbomError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.send_sbom(result?.retrieved).await?;
        Ok(())
    }
}

impl SendVisitor {
    async fn send_sbom(&self, sbom: RetrievedSbom) -> Result<(), SendError> {
        log::debug!(
            "Sending: {} (modified: {:?})",
            sbom.url,
            sbom.metadata.last_modification
        );

        let RetrievedSbom {
            data,
            discovered: DiscoveredSbom { url, .. },
            ..
        } = sbom;

        let name = url
            .path_segments()
            .and_then(|p| p.last())
            .unwrap_or_else(|| url.path());

        if !(name.ends_with(".json") || name.ends_with(".json.bz2")) {
            log::warn!("Skipping unknown file: {name}");
            return Ok(());
        }

        let bzip2 = name.ends_with(".bz2");

        self.send(url.as_str(), data, |mut request| {
            request = request.query(&[("id", name)]);
            if bzip2 {
                request.header(header::CONTENT_ENCODING, "bzip2")
            } else {
                request
            }
        })
        .await
    }
}
