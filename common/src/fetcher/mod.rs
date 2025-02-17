//! Fetching remote resources

mod data;
use backon::{ExponentialBuilder, Retryable};
pub use data::*;

use reqwest::{Client, ClientBuilder, IntoUrl, Method, Response};
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;
use url::Url;

/// Fetch data using HTTP.
///
/// This is some functionality sitting on top an HTTP client, allowing for additional options like
/// retries.
#[derive(Clone, Debug)]
pub struct Fetcher {
    client: Client,
    retries: usize,
}

/// Error when retrieving
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
}

/// Options for the [`Fetcher`]
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct FetcherOptions {
    pub timeout: Duration,
    pub retries: usize,
}

impl FetcherOptions {
    /// Create a new instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout.
    pub fn timeout(mut self, timeout: impl Into<Duration>) -> Self {
        self.timeout = timeout.into();
        self
    }

    /// Set the number of retries.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }
}

impl Default for FetcherOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            retries: 5,
        }
    }
}

impl From<Client> for Fetcher {
    fn from(client: Client) -> Self {
        Self::with_client(client, FetcherOptions::default())
    }
}

impl Fetcher {
    /// Create a new downloader from options
    pub async fn new(options: FetcherOptions) -> anyhow::Result<Self> {
        let client = ClientBuilder::new().timeout(options.timeout);

        Ok(Self::with_client(client.build()?, options))
    }

    /// Create a fetcher providing an existing client.
    fn with_client(client: Client, options: FetcherOptions) -> Self {
        Self {
            client,
            retries: options.retries,
        }
    }

    async fn new_request(
        &self,
        method: Method,
        url: Url,
    ) -> Result<reqwest::RequestBuilder, reqwest::Error> {
        Ok(self.client.request(method, url))
    }

    /// fetch data, using a GET request.
    pub async fn fetch<D: Data>(&self, url: impl IntoUrl) -> Result<D, Error> {
        log::debug!("Fetching: {}", url.as_str());
        self.fetch_processed(url, TypedProcessor::<D>::new()).await
    }

    /// fetch data, using a GET request, processing the response data.
    pub async fn fetch_processed<D: DataProcessor>(
        &self,
        url: impl IntoUrl,
        processor: D,
    ) -> Result<D::Type, Error> {
        // if the URL building fails, there is no need to re-try, abort now.
        let url = url.into_url()?;

        let retries = self.retries;
        let backoff = ExponentialBuilder::default();

        (|| async {
            match self.fetch_once(url.clone(), &processor).await {
                Ok(result) => Ok(result),
                Err(err) => {
                    log::info!("Failed to retrieve: {err}");
                    Err(err)
                }
            }
        })
        .retry(&backoff.with_max_times(retries))
        .await
    }

    async fn fetch_once<D: DataProcessor>(
        &self,
        url: Url,
        processor: &D,
    ) -> Result<D::Type, Error> {
        let response = self.new_request(Method::GET, url).await?.send().await?;

        Ok(processor.process(response).await?)
    }
}

/// Processing data returned by a request.
pub trait DataProcessor {
    type Type: Sized;
    fn process(
        &self,
        response: reqwest::Response,
    ) -> impl Future<Output = Result<Self::Type, reqwest::Error>>;
}

struct TypedProcessor<D: Data> {
    _marker: PhantomData<D>,
}

impl<D: Data> TypedProcessor<D> {
    pub const fn new() -> Self {
        Self {
            _marker: PhantomData::<D>,
        }
    }
}

/// Extract response payload which implements [`Data`].
impl<D: Data> DataProcessor for TypedProcessor<D> {
    type Type = D;

    async fn process(&self, response: Response) -> Result<Self::Type, reqwest::Error> {
        D::from_response(response).await
    }
}
