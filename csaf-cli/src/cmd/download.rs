use crate::cmd::{DiscoverArguments, ValidationArguments};
use crate::common::walk_standard;
use anyhow::{anyhow, Context};
use std::path::PathBuf;

/// Download
#[derive(clap::Args, Debug)]
pub struct Download {
    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    /// Output path, defaults to the local directory.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

impl Download {
    pub async fn run(self) -> anyhow::Result<()> {
        let base = match self.output {
            Some(base) => base,
            None => std::env::current_dir().context("Get current working directory")?,
        };

        walk_standard(self.discover, self.validation, move |advisory| {
            let base = base.clone();
            async move {
                // if we fail, we fail!
                let advisory = advisory?;

                log::info!("Downloading: {}", advisory.url);

                let file = PathBuf::from(advisory.url.path())
                    .file_name()
                    .map(|file| base.join(file))
                    .ok_or_else(|| anyhow!("Unable to detect file name"))?;

                log::debug!("Writing {}", file.display());
                std::fs::write(file, &advisory.data).context("Write advisory")?;

                Ok(())
            }
        })
        .await?;

        Ok(())
    }
}
