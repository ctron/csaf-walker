//! Send data off to a remote API

pub mod provider;

mod error;

pub use error::*;
use std::path::PathBuf;

use crate::sender::provider::{TokenInjector, TokenProvider};
use anyhow::Context;
use reqwest::{header, IntoUrl, Method, RequestBuilder};
use std::sync::Arc;
use std::time::Duration;

pub struct HttpSender {
    client: reqwest::Client,
    provider: Arc<dyn TokenProvider>,
}

/// Options for the [`HttpSender`].
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub connect_timeout: Option<Duration>,
    pub timeout: Option<Duration>,
    pub additional_root_certificates: Vec<PathBuf>,
}

impl Options {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connect_timeout(mut self, connect_timeout: impl Into<Duration>) -> Self {
        self.connect_timeout = Some(connect_timeout.into());
        self
    }

    pub fn timeout(mut self, timeout: impl Into<Duration>) -> Self {
        self.connect_timeout = Some(timeout.into());
        self
    }

    pub fn additional_root_certificates<I>(mut self, additional_root_certificates: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.additional_root_certificates = Vec::from_iter(additional_root_certificates);
        self
    }

    pub fn add_additional_root_certificate(
        mut self,
        additional_root_certificate: impl Into<PathBuf>,
    ) -> Self {
        self.additional_root_certificates
            .push(additional_root_certificate.into());
        self
    }

    pub fn extend_additional_root_certificate<I>(mut self, additional_root_certificates: I) -> Self
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.additional_root_certificates
            .extend(additional_root_certificates);
        self
    }
}

const USER_AGENT: &str = concat!("CSAF-Walker/", env!("CARGO_PKG_VERSION"));

impl HttpSender {
    pub async fn new<P>(provider: P, options: Options) -> Result<Self, anyhow::Error>
    where
        P: TokenProvider + 'static,
    {
        let mut headers = header::HeaderMap::new();
        headers.insert("User-Agent", header::HeaderValue::from_static(USER_AGENT));

        let mut client = reqwest::ClientBuilder::new().default_headers(headers);

        if let Some(connect_timeout) = options.connect_timeout {
            client = client.connect_timeout(connect_timeout);
        }

        if let Some(timeout) = options.timeout {
            client = client.timeout(timeout);
        }

        for cert in options.additional_root_certificates {
            let cert = std::fs::read(&cert)
                .with_context(|| format!("Reading certificate: {}", cert.display()))?;
            let cert = reqwest::tls::Certificate::from_pem(&cert)?;
            client = client.add_root_certificate(cert);
        }

        Ok(Self {
            client: client.build()?,
            provider: Arc::new(provider),
        })
    }

    /// build a new request, injecting the token
    pub async fn request<U: IntoUrl>(
        &self,
        method: Method,
        url: U,
    ) -> Result<RequestBuilder, Error> {
        self.client
            .request(method, url)
            .inject_token(&self.provider)
            .await
    }
}
