use super::*;
use crate::csaf::{
    retrieve::{RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor},
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use csaf_walker::discover::DiscoveredAdvisory;

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedAdvisoryError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

impl RetrievedVisitor for SendVisitor {
    type Error = SendRetrievedAdvisoryError;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.send_retrieved_advisory(result?).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendValidatedAdvisoryError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

impl ValidatedVisitor for SendVisitor {
    type Error = SendValidatedAdvisoryError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext<'_>) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.send_retrieved_advisory(result?.retrieved).await?;
        Ok(())
    }
}

impl SendVisitor {
    async fn send_retrieved_advisory(&self, advisory: RetrievedAdvisory) -> Result<(), SendError> {
        log::debug!(
            "Sending: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let RetrievedAdvisory {
            data,
            discovered: DiscoveredAdvisory { url, .. },
            ..
        } = advisory;

        self.send_advisory(url.as_str(), data).await
    }

    pub async fn send_advisory(&self, name: &str, data: Bytes) -> Result<(), SendError> {
        self.send(name, data, |request| {
            request.header(header::CONTENT_TYPE, "application/json")
        })
        .await
    }
}
