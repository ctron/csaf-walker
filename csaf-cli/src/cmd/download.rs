use crate::cmd::{ClientArguments, DiscoverArguments, StoreArguments, ValidationArguments};
use crate::common::walk_standard;
use crate::store::store_advisory;
use anyhow::Context;
use std::path::PathBuf;

/// Download
#[derive(clap::Args, Debug)]
pub struct Download {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    store: StoreArguments,

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

        let skip_attr = self.store.no_xattrs;

        walk_standard(
            self.client,
            self.discover,
            self.validation,
            move |advisory| {
                let base = base.clone();
                async move {
                    // if we fail, we fail!
                    let advisory = advisory?;

                    store_advisory(&base, advisory, skip_attr).await?;

                    Ok(())
                }
            },
        )
        .await?;

        Ok(())
    }
}
