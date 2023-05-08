use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
use crate::common::walk_visitor;
use anyhow::{anyhow, Context};
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor,
};
use csaf_walker::visitors::skip::SkipExistingVisitor;
use std::path::PathBuf;
use tokio::fs;

/// Sync only what changed
#[derive(clap::Args, Debug)]
pub struct Sync {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    /// Output path, defaults to the local directory.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

impl Sync {
    pub async fn run(self) -> anyhow::Result<()> {
        let base = match self.output {
            Some(base) => base,
            None => std::env::current_dir().context("Get current working directory")?,
        };

        let options: ValidationOptions = self.validation.into();

        walk_visitor(self.client, self.discover, move |fetcher| async move {
            let visitor = {
                let base = base.clone();

                RetrievingVisitor::new(
                    fetcher.clone(),
                    ValidationVisitor::new(
                        fetcher.clone(),
                        move |advisory: Result<ValidatedAdvisory, ValidationError>| {
                            let base = base.clone();
                            async move {
                                match advisory {
                                    Ok(advisory) => {
                                        log::info!("Downloading: {}", advisory.url);

                                        let file = PathBuf::from(advisory.url.path())
                                            .file_name()
                                            .map(|file| base.join(file))
                                            .ok_or_else(|| anyhow!("Unable to detect file name"))?;

                                        log::debug!("Writing {}", file.display());
                                        fs::write(file, &advisory.data)
                                            .await
                                            .context("Write advisory")?;
                                    }
                                    Err(err) => {
                                        log::warn!("Skipping erroneous advisory: {err}");
                                    }
                                }

                                Ok::<_, anyhow::Error>(())
                            }
                        },
                    )
                    .with_options(options),
                )
            };

            Ok(SkipExistingVisitor {
                visitor,
                output: base,
            })
        })
        .await?;

        Ok(())
    }
}
