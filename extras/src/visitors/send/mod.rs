use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{header, Body, Method, StatusCode, Url};
use std::time::Duration;
use walker_common::sender::{self, HttpSender};

#[cfg(feature = "sbom-walker")]
mod sbom;
#[cfg(feature = "sbom-walker")]
pub use sbom::*;

#[cfg(feature = "csaf-walker")]
mod csaf;
#[cfg(feature = "csaf-walker")]
pub use csaf::*;

#[cfg(feature = "clap")]
mod clap;
#[cfg(feature = "clap")]
pub use self::clap::*;

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
#[non_exhaustive]
#[derive(Clone)]
pub struct SendVisitor {
    /// The target endpoint
    pub url: Url,

    /// The HTTP client to use
    pub sender: HttpSender,

    /// The number of retries in case of a server or transmission failure
    pub retries: usize,

    /// The delay between retries
    pub retry_delay: Option<Duration>,
}

impl SendVisitor {
    pub fn new(url: impl Into<Url>, sender: HttpSender) -> Self {
        Self {
            url: url.into(),
            sender,
            retries: 0,
            retry_delay: None,
        }
    }

    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn retry_delay(mut self, retry_delay: impl Into<Duration>) -> Self {
        self.retry_delay = Some(retry_delay.into());
        self
    }
}

/// The default amount of time to wait before trying
const DEFAULT_RETRY_DELAY: Duration = Duration::from_secs(5);

pub enum SendOnceError {
    Temporary(SendError),
    Permanent(SendError),
}

impl SendVisitor {
    /// Send request once
    async fn send_once<F>(
        &self,
        name: &str,
        data: Bytes,
        customizer: F,
    ) -> Result<(), SendOnceError>
    where
        F: FnOnce(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let request = self
            .sender
            .request(Method::POST, self.url.clone())
            .await
            .map_err(|err| SendOnceError::Temporary(err.into()))?
            .body(Body::from(data));
        let request = customizer(request);
        let response = request
            .send()
            .await
            .map_err(|err| SendOnceError::Temporary(err.into()))?;

        let status = response.status();

        if status.is_success() {
            log::debug!("Uploaded {} -> {}", name, response.status());
            Ok(())
        } else if status.is_client_error() {
            log::warn!("Failed to upload, payload rejected {name} -> {status}",);
            Err(SendOnceError::Permanent(SendError::Client(status)))
        } else if status.is_server_error() {
            log::warn!("Failed to upload, server error {name} -> {status}",);
            Err(SendOnceError::Temporary(SendError::Server(status)))
        } else {
            Err(SendOnceError::Permanent(SendError::UnexpectedStatus(
                status,
            )))
        }
    }

    /// Send request, retry in case of temporary errors
    async fn send<F>(&self, name: &str, data: Bytes, customizer: F) -> Result<(), SendError>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let mut retries = self.retries;
        loop {
            match self.send_once(name, data.clone(), &customizer).await {
                Ok(()) => break Ok(()),
                Err(SendOnceError::Permanent(err)) => break Err(err),
                Err(SendOnceError::Temporary(err)) if retries == 0 => break Err(err),
                Err(SendOnceError::Temporary(_)) => {
                    log::debug!("Failed with a temporary error, retrying ...");
                }
            }

            // sleep, then try again

            tokio::time::sleep(self.retry_delay.unwrap_or(DEFAULT_RETRY_DELAY)).await;
            log::info!("Retrying ({retries} attempts left)");
            retries -= 1;
        }
    }
}
