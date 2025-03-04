use crate::progress::{Progress, ProgressBar};
use anyhow::bail;
use std::path::{Path, PathBuf};
use tracing::instrument;

/// A tool to build a [`Scooper`].
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct ScooperBuilder {
    pub sources: Vec<PathBuf>,
    pub delete: bool,
    pub processed: Option<PathBuf>,
    pub failed: Option<PathBuf>,
}

impl ScooperBuilder {
    pub fn build(self) -> anyhow::Result<Scooper> {
        let files = self.discover()?;
        Ok(Scooper {
            builder: self,
            files,
        })
    }

    /// Discover files to upload
    fn discover(&self) -> anyhow::Result<Vec<PathBuf>> {
        Ok(self
            .sources
            .iter()
            .map(|path| Self::discover_one(path))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect())
    }

    fn discover_one(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
        log::debug!("Discovering: {}", path.display());

        if !path.exists() {
            bail!("{} does not exist", path.display());
        } else if path.is_file() {
            log::debug!("Is a file");
            Ok(vec![path.to_path_buf()])
        } else if path.is_dir() {
            log::debug!("Is a directory");
            let mut result = Vec::new();

            for path in walkdir::WalkDir::new(path).into_iter() {
                let path = path?;
                if path.file_type().is_file() {
                    result.push(path.path().to_path_buf());
                }
            }

            Ok(result)
        } else {
            log::warn!("Is something unknown: {}", path.display());
            Ok(vec![])
        }
    }
}

/// A tool to scoop up files
pub struct Scooper {
    builder: ScooperBuilder,
    files: Vec<PathBuf>,
}

impl Scooper {
    #[instrument(skip_all, err)]
    pub async fn process<F, P>(self, progress: P, processor: F) -> anyhow::Result<()>
    where
        for<'a> F: AsyncFn(&'a Path) -> anyhow::Result<()> + 'a,
        P: Progress,
    {
        if let Some(processed) = &self.builder.processed {
            tokio::fs::create_dir_all(processed).await?;
        }
        if let Some(failed) = &self.builder.failed {
            tokio::fs::create_dir_all(failed).await?;
        }

        let total = self.files.len();
        let mut errors = 0usize;

        let mut p = progress.start(total);
        for file in self.files {
            p.set_message(
                file.file_name()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_else(|| file.to_string_lossy())
                    .to_string(),
            )
            .await;
            match processor(&file).await {
                Ok(()) => {
                    if self.builder.delete {
                        tokio::fs::remove_file(&file).await?;
                    } else if let Some(processed) = &self.builder.processed {
                        tokio::fs::copy(&file, processed.join(&file)).await?;
                        tokio::fs::remove_file(&file).await?;
                    }
                }
                Err(err) => {
                    errors += 1;
                    log::error!("Failed to upload file: {err}");
                    if let Some(failed) = &self.builder.failed {
                        tokio::fs::copy(&file, failed.join(&file)).await?;
                        tokio::fs::remove_file(&file).await?;
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
