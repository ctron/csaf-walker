//! Fetching remote resources

mod data;

pub use data::*;

use async_trait::async_trait;
use reqwest::{Client, ClientBuilder, IntoUrl, Method, Response};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::Duration;
use url::Url;

/// Fetch data using HTTP.
///
/// This is some functionality sitting on top an HTTP client, allowing for additional options likes
/// retries.
#[derive(Clone, Debug)]
pub struct Fetcher {
    client: Client,
    retries: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
}

#[derive(Clone, Debug)]
pub struct FetcherOptions {
    pub timeout: Duration,
    pub retries: usize,
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

        let mut retries = self.retries;

        loop {
            match self.fetch_once(url.clone(), &processor).await {
                Ok(result) => break Ok(result),
                Err(err) => {
                    if retries > 0 {
                        // TODO: consider adding a back-off delay
                        retries -= 1;
                    } else {
                        break Err(err);
                    }
                }
            }
        }
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

#[async_trait(?Send)]
pub trait DataProcessor {
    type Type: Sized;
    async fn process(&self, response: reqwest::Response) -> Result<Self::Type, reqwest::Error>;
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

#[async_trait(?Send)]
impl<D: Data> DataProcessor for TypedProcessor<D> {
    type Type = D;

    async fn process(&self, response: Response) -> Result<Self::Type, reqwest::Error> {
        D::from_response(response).await
    }
}
