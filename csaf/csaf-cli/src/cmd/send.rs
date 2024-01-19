use crate::{
    cmd::{DiscoverArguments, FilterArguments, SendArguments, SkipArguments},
    common::{walk_visitor, DiscoverConfig},
};
use csaf_walker::{
    retrieve::RetrievingVisitor, validation::ValidationVisitor, visitors::skip::SkipFailedVisitor,
};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};
use walker_extras::visitors::SendVisitor;

/// Sync only what changed, send to a remote endpoint
#[derive(clap::Args, Debug)]
pub struct Send {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[command(flatten)]
    send: SendArguments,

    /// Disable validation of digest and signatures (DANGER!)
    #[arg(long)]
    disable_validation: bool,
}

impl Send {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let send: SendVisitor = self.send.into_visitor().await?;

        if self.disable_validation {
            log::warn!("Validation is disabled");
        }

        let since = Since::new(
            self.skip.since,
            self.skip.since_file,
            self.skip
                .since_file_offset
                .map(|d| d.into())
                .unwrap_or_default(),
        )?;

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.filter,
            self.runner,
            move |source| async move {
                let visitor = {
                    RetrievingVisitor::new(source.clone(), {
                        ValidationVisitor::new(SkipFailedVisitor {
                            skip_failures: self.disable_validation,
                            visitor: send,
                        })
                        .with_options(options)
                    })
                };

                Ok(visitor)
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
