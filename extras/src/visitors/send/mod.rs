use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Body, Method, StatusCode, Url};
use walker_common::sender::{self, HttpSender};

#[cfg(feature = "sbom-walker")]
mod sbom;
#[cfg(feature = "sbom-walker")]
pub use sbom::*;

#[cfg(feature = "csaf-walker")]
mod csaf;
#[cfg(feature = "csaf-walker")]
pub use csaf::*;

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Sender(#[from] sender::Error),
    #[error(transparent)]
    Request(#[from] reqwest::Error),
    #[error("client error: {0}")]
    Client(StatusCode),
    #[error("server error: {0}")]
    Server(StatusCode),
    #[error("unexpected status: {0}")]
    UnexpectedStatus(StatusCode),
}

/// Stores all data so that it can be used as a [`crate::source::Source`] later.
pub struct SendVisitor {
    /// The target endpoint
    pub url: Url,

    /// The HTTP client to use
    pub sender: HttpSender,
}

impl SendVisitor {
    async fn send<F>(&self, name: &str, data: Bytes, customizer: F) -> Result<(), SendError>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let request = self
            .sender
            .request(Method::POST, self.url.clone())
            .await?
            .body(Body::from(data));
        let request = customizer(request);
        let response = request.send().await?;

        let status = response.status();

        if status.is_success() {
            log::debug!("Uploaded {} -> {}", name, response.status());
            Ok(())
        } else if status.is_client_error() {
            log::warn!("Failed to upload, payload rejected {name} -> {status}",);
            Err(SendError::Client(status))
        } else if status.is_server_error() {
            log::warn!("Failed to upload, server error {name} -> {status}",);
            Err(SendError::Server(status))
        } else {
            Err(SendError::UnexpectedStatus(status))
        }
    }
}
