use crate::discover::DiscoveredSbom;
use crate::retrieve::{RetrievalContext, RetrievalError, RetrievedSbom, RetrievedVisitor};
use crate::validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError};
use async_trait::async_trait;
use http::header;
use reqwest::{Body, Method, StatusCode};
use url::Url;
use walker_common::sender::{self, HttpSender};

/// Stores all data so that it can be used as a [`crate::source::Source`] later.
pub struct SendVisitor {
    /// The target endpoint
    pub url: Url,

    /// The HTTP client to use
    pub sender: HttpSender,
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Sender(#[from] sender::Error),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("server error: {0}")]
    Server(StatusCode),
    #[error("unexpected status: {0}")]
    UnexpectedStatus(StatusCode),
}

#[derive(Debug, thiserror::Error)]
pub enum SendRetrievedError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

#[derive(Debug, thiserror::Error)]
pub enum SendValidatedError {
    #[error(transparent)]
    Store(#[from] SendError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[async_trait(?Send)]
impl RetrievedVisitor for SendVisitor {
    type Error = SendRetrievedError;
    type Context = ();

    async fn visit_context(&self, _: &RetrievalContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.send(result?).await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl ValidatedVisitor for SendVisitor {
    type Error = SendValidatedError;
    type Context = ();

    async fn visit_context(&self, _: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.send(result?.retrieved).await?;
        Ok(())
    }
}

impl SendVisitor {
    async fn send(&self, advisory: RetrievedSbom) -> Result<(), SendError> {
        log::debug!(
            "Sending: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let RetrievedSbom {
            data,
            discovered: DiscoveredSbom { url, .. },
            ..
        } = advisory;

        let response = self
            .sender
            .request(Method::POST, self.url.clone())
            .await?
            .body(Body::from(data))
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            log::debug!("Uploaded {} -> {}", url, response.status());
            Ok(())
        } else if status.is_client_error() {
            log::warn!("Failed to upload, payload rejected {url} -> {status}",);
            Ok(())
        } else if status.is_server_error() {
            log::warn!("Failed to upload, server error {url} -> {status}",);
            Err(SendError::Server(status))
        } else {
            Err(SendError::UnexpectedStatus(status))
        }
    }
}
