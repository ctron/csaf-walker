use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};

/// Data which can be extracted from a [`Response`].
#[async_trait(?Send)]
pub trait Data: Sized {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error>;
}

/// String data
#[async_trait(?Send)]
impl Data for String {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.text().await
    }
}

/// BLOB data
#[async_trait(?Send)]
impl Data for Bytes {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.bytes().await
    }
}

/// A new-type wrapping [`String`].
pub struct Text(pub String);

#[async_trait(?Send)]
impl Data for Text {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.text().await.map(Self)
    }
}

impl Text {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Text {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Text {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// JSON based data.
#[derive(Clone)]
pub struct Json<D>(pub D)
where
    D: DeserializeOwned;

#[async_trait(?Send)]
impl<D> Data for Json<D>
where
    D: DeserializeOwned,
{
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        response.error_for_status()?.json().await.map(Self)
    }
}

impl<D: DeserializeOwned> Json<D> {
    #[inline]
    pub fn into_inner(self) -> D {
        self.0
    }
}

impl<D: DeserializeOwned> Deref for Json<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D: DeserializeOwned> DerefMut for Json<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait(?Send)]
impl<D: Data> Data for Option<D> {
    async fn from_response(response: Response) -> Result<Self, reqwest::Error> {
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(D::from_response(response).await?))
    }
}
