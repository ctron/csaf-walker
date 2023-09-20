use crate::discover::DiscoveredSbom;
use crate::source::{HttpSource, Source};
use async_trait::async_trait;

/// A common source type, dispatching to the known implementations.
///
/// This helps creating implementations which don't need to know the exact type. Unfortunately we
/// cannot just "box" this, as the [`Source`] needs to implement [`Clone`], which requires [`Sized`],
/// which prevents us from using `dyn` ("cannot be made into an object").
///
/// There may be a better way around this, feel free to send a PR ;-)
#[derive(Clone)]
pub enum DispatchSource {
    Http(HttpSource),
}

impl From<HttpSource> for DispatchSource {
    fn from(value: HttpSource) -> Self {
        Self::Http(value)
    }
}

#[async_trait(?Send)]
impl Source for DispatchSource {
    type Error = anyhow::Error;

    async fn load_index(&self) -> Result<Vec<DiscoveredSbom>, Self::Error> {
        match self {
            Self::Http(source) => Ok(source.load_index().await?),
        }
    }
}
