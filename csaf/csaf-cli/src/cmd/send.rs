use crate::{
    cmd::{DiscoverArguments, SendArguments, SkipArguments},
    common::{walk_visitor, DiscoverConfig},
};
use csaf_walker::{
    retrieve::RetrievingVisitor, validation::ValidationVisitor, visitors::send::SendVisitor,
};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};

/// Sync only what changed, and don't validate.
#[derive(clap::Args, Debug)]
pub struct Send {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[command(flatten)]
    send: SendArguments,
}

impl Send {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let send: SendVisitor = self.send.into_visitor().await?;

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
            self.runner,
            move |source| async move {
                let visitor = {
                    RetrievingVisitor::new(
                        source.clone(),
                        ValidationVisitor::new(send).with_options(options),
                    )
                };

                Ok(visitor)
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
