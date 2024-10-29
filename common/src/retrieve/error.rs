use crate::utils::url::Urlify;
use std::fmt::{Debug, Display};
use url::Url;

#[derive(Clone, Debug, thiserror::Error)]
pub enum RetrievalError<D, SE>
where
    D: Urlify,
    SE: Debug + Display,
{
    #[error("source error: {err}")]
    Source { err: SE, discovered: D },
}

impl<D, SE> RetrievalError<D, SE>
where
    D: Urlify,
    SE: Debug + Display,
{
    pub fn discovered(&self) -> &D {
        match self {
            Self::Source { discovered, .. } => discovered,
        }
    }
}

impl<SE, D> Urlify for RetrievalError<D, SE>
where
    D: Urlify,
    SE: Debug + Display,
{
    fn url(&self) -> &Url {
        match self {
            Self::Source { discovered, .. } => &discovered.url(),
        }
    }
}
