use crate::{
    cmd::{DiscoverArguments, FilterArguments, SkipArguments, StoreArguments},
    common::walk_visitor,
};
use csaf_walker::discover::DiscoverConfig;
use csaf_walker::{
    retrieve::RetrievingVisitor,
    validation::ValidationVisitor,
    visitors::{skip::SkipExistingVisitor, store::StoreVisitor},
};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    since::Since,
    validate::ValidationOptions,
};

/// Sync only what changed, and alidate.
#[derive(clap::Args, Debug)]
pub struct Sync {
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
    store: StoreArguments,
}

impl Sync {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let store: StoreVisitor = self.store.try_into()?;
        let base = store.base.clone();

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
            async move |source| {
                let visitor = {
                    RetrievingVisitor::new(
                        source,
                        ValidationVisitor::new(store).with_options(options),
                    )
                };

                Ok(SkipExistingVisitor {
                    visitor,
                    output: base,
                    since: since.since,
                })
            },
        )
        .await?;

        since.store()?;

        Ok(())
    }
}
