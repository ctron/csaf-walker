use crate::{
    retrieve::{RetrievalError, RetrievedDocument},
    source::Source,
    utils::url::Urlify,
};
use std::fmt::{Debug, Display, Formatter};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError<S>
where
    S: Source,
{
    Retrieval(RetrievalError<<S::Retrieved as RetrievedDocument>::Discovered, S>),
    DigestMismatch {
        expected: String,
        actual: String,
        retrieved: S::Retrieved,
    },
    Signature {
        error: anyhow::Error,
        retrieved: S::Retrieved,
    },
}

impl<S> Urlify for ValidationError<S>
where
    S: Source,
{
    fn url(&self) -> &Url {
        match self {
            Self::Retrieval(err) => err.url(),
            Self::DigestMismatch { retrieved, .. } => &retrieved.url(),
            Self::Signature { retrieved, .. } => &retrieved.url(),
        }
    }
}

impl<S> Display for ValidationError<S>
where
    S: Source,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retrieval(err) => write!(f, "Retrieval error: {err}"),
            Self::DigestMismatch {
                expected,
                actual,
                retrieved,
            } => write!(
                f,
                "Digest mismatch - expected: {expected}, actual: {actual} ({})",
                retrieved.url()
            ),
            Self::Signature { error, retrieved } => {
                write!(f, "Invalid signature: {error} ({})", retrieved.url())
            }
        }
    }
}
