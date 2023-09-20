//! The actual walker

use crate::discover::{DiscoveredSbom, DiscoveredVisitor};
use crate::source::Source;
use futures::{stream, StreamExt, TryFutureExt, TryStream, TryStreamExt};
use std::fmt::Debug;
use std::sync::Arc;
use url::ParseError;
use walker_common::progress::Progress;

#[derive(Debug, thiserror::Error)]
pub enum Error<VE, SE>
where
    VE: std::fmt::Display + Debug,
    SE: std::fmt::Display + Debug,
{
    #[error("Source error: {0}")]
    Source(SE),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("Visitor error: {0}")]
    Visitor(VE),
}

pub struct Walker<S: Source> {
    source: S,
    progress: Progress,
}

impl<S: Source> Walker<S> {
    pub fn new(source: S) -> Self {
        Self {
            source,
            progress: Progress::default(),
        }
    }

    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.progress = progress;
        self
    }

    pub async fn walk<V>(self, visitor: V) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        let index = self.source.load_index().await.map_err(Error::Source)?;
        let progress = self.progress.start(index.len());

        for sbom in index {
            log::debug!("  Discovered SBOM: {sbom:?}");
            progress.set_message(
                sbom.url
                    .path()
                    .rsplit_once('/')
                    .map(|(_, s)| s)
                    .unwrap_or(sbom.url.as_str())
                    .to_string()
                    .into(),
            );
            visitor.visit_sbom(sbom).await.map_err(Error::Visitor)?;
            progress.tick();
        }

        Ok(())
    }

    pub async fn walk_parallel<V>(
        self,
        limit: usize,
        visitor: V,
    ) -> Result<(), Error<V::Error, S::Error>>
    where
        V: DiscoveredVisitor,
    {
        let visitor = Arc::new(visitor);

        stream::iter(self.source.load_index().await.map_err(Error::Source)?)
            .map(Ok)
            .try_for_each_concurrent(limit, |sbom| {
                log::debug!("Discovered advisory: {}", sbom.url);
                let visitor = visitor.clone();

                async move { visitor.visit_sbom(sbom).map_err(Error::Visitor).await }
            })
            .await?;

        Ok(())
    }
}
