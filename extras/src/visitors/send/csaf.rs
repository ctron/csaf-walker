use super::*;
use crate::csaf::{
    retrieve::{RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor},
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use async_trait::async_trait;
use csaf_walker::discover::DiscoveredAdvisory;

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedAdvisoryError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

#[async_trait(?Send)]
impl RetrievedVisitor for SendVisitor {
    type Error = SendRetrievedAdvisoryError;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.send_csaf(result?).await?;
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

#[async_trait(?Send)]
impl ValidatedVisitor for SendVisitor {
    type Error = SendValidatedAdvisoryError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.send_csaf(result?.retrieved).await?;
        Ok(())
    }
}

impl SendVisitor {
    async fn send_csaf(&self, advisory: RetrievedAdvisory) -> Result<(), SendError> {
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

        self.send(url.as_str(), data, |r| r).await
    }
}
