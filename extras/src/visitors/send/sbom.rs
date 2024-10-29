use super::*;
use crate::sbom::{
    discover::DiscoveredSbom,
    retrieve::{RetrievalContext, RetrievedSbom, RetrievedVisitor},
    validation::{ValidatedSbom, ValidatedVisitor, ValidationContext},
};
use reqwest::header;
use sbom_walker::source::Source;
use walker_common::{retrieve::RetrievalError, validate::ValidationError};

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedSbomError<S: Source> {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError<DiscoveredSbom, S>),
}

impl<S: Source> RetrievedVisitor<S> for SendVisitor {
    type Error = SendRetrievedSbomError<S>;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError<DiscoveredSbom, S>>,
    ) -> Result<(), Self::Error> {
        self.send_sbom(result?).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendValidatedSbomError<S: Source> {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Validation(#[from] ValidationError<RetrievedSbom, S>),
}

impl<S: Source> ValidatedVisitor<S> for SendVisitor {
    type Error = SendValidatedSbomError<S>;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError<RetrievedSbom, S>>,
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
            request = request
                .query(&[("id", name)])
                .header(header::CONTENT_TYPE, "application/json");
            if bzip2 {
                request.header(header::CONTENT_ENCODING, "bzip2")
            } else {
                request
            }
        })
        .await
    }
}
