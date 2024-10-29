use crate::{
    retrieve::{RetrievalError, RetrievedDocument},
    source::Source,
    utils::url::Urlify,
};
use std::fmt::{Debug, Display, Formatter};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError<D, S>
where
    D: RetrievedDocument,
    S: Source,
{
    Retrieval(RetrievalError<D::Discovered, S>),
    DigestMismatch {
        expected: String,
        actual: String,
        retrieved: D,
    },
    Signature {
        error: anyhow::Error,
        retrieved: D,
    },
}

impl<D, S> Urlify for ValidationError<D, S>
where
    D: RetrievedDocument,
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

impl<D, S> Display for ValidationError<D, S>
where
    D: RetrievedDocument,
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
