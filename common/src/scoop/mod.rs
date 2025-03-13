mod source;

pub use source::*;

use crate::progress::{Progress, ProgressBar};
use anyhow::bail;
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use tracing::instrument;

/// A tool to build a [`Scooper`].
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct ScooperBuilder {
    pub sources: Vec<Source>,
    pub delete: bool,
    pub processed: Option<String>,
    pub failed: Option<String>,
}

impl ScooperBuilder {
    pub async fn build(self) -> anyhow::Result<Scooper> {
        let sources = self.discover().await?;
        Ok(Scooper {
            builder: self,
            sources,
        })
    }

    /// Discover files to upload
    async fn discover(&self) -> anyhow::Result<Vec<Source>> {
        Ok(stream::iter(&self.sources)
            .then(async |source| source.clone().discover().await)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .flatten()
            .collect())
    }
}

/// A tool to scoop up files
pub struct Scooper {
    builder: ScooperBuilder,
    sources: Vec<Source>,
}

impl Scooper {
    #[instrument(skip_all, err)]
    pub async fn process<F, P>(self, progress: P, processor: F) -> anyhow::Result<()>
    where
        for<'a> F: AsyncFn(&'a str, Bytes) -> anyhow::Result<()> + 'a,
        P: Progress,
    {
        let total = self.sources.len();
        let mut errors = 0usize;

        let mut p = progress.start(total);
        for source in self.sources {
            p.set_message(source.name().to_string()).await;
            match processor(source.name().as_ref(), source.load().await?).await {
                Ok(()) => {
                    if self.builder.delete {
                        source.delete().await?;
                    } else if let Some(processed) = &self.builder.processed {
                        source.r#move(processed).await?;
                    }
                }
                Err(err) => {
                    errors += 1;
                    log::error!("Failed to upload file: {err}");
                    if let Some(failed) = &self.builder.failed {
                        source.r#move(failed).await?;
                    }
                }
            }
            p.tick().await;
        }

        p.finish().await;

        match errors {
            0 => {
                log::info!("Uploaded {total} files");
                Ok(())
            }
            n => bail!("Failed to upload {n} (of {total}) files"),
        }
    }
}
