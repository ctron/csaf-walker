use crate::{source::Source, utils::url::Urlify};
use std::fmt::Debug;
use url::Url;

#[derive(Clone, Debug, thiserror::Error)]
pub enum RetrievalError<D, S>
where
    D: Urlify,
    S: Source,
{
    #[error("source error: {err}")]
    Source { err: S::Error, discovered: D },
}

impl<D, S> RetrievalError<D, S>
where
    D: Urlify,
    S: Source,
{
    pub fn discovered(&self) -> &D {
        match self {
            Self::Source { discovered, .. } => discovered,
        }
    }
}

impl<S, D> Urlify for RetrievalError<D, S>
where
    D: Urlify,
    S: Source,
{
    fn url(&self) -> &Url {
        match self {
            Self::Source { discovered, .. } => discovered.url(),
        }
    }
}
