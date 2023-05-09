use crate::cmd::{ClientArguments, DiscoverArguments, StoreArguments, ValidationArguments};
use crate::common::walk_visitor;
use crate::store::store_advisory;
use anyhow::Context;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor,
};
use csaf_walker::visitors::skip::SkipExistingVisitor;
use std::path::PathBuf;

/// Sync only what changed
#[derive(clap::Args, Debug)]
pub struct Sync {
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

impl Sync {
    pub async fn run(self) -> anyhow::Result<()> {
        let base = match self.output {
            Some(base) => base,
            None => std::env::current_dir().context("Get current working directory")?,
        };

        let options: ValidationOptions = self.validation.into();
        let skip_attrs = self.store.no_xattrs;

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
                                        store_advisory(&base, advisory, skip_attrs).await?;
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
