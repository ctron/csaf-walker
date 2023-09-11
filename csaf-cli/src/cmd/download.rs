use crate::{
    cmd::{
        ClientArguments, DiscoverArguments, RunnerArguments, SkipArguments, StoreArguments,
        ValidationArguments,
    },
    common::{walk_visitor, DiscoverConfig},
    since::Since,
};
use csaf_walker::{
    progress::Progress,
    retrieve::RetrievingVisitor,
    visitors::{skip::SkipExistingVisitor, store::StoreVisitor},
};

/// Like sync, but doesn't validate.
#[derive(clap::Args, Debug)]
pub struct Download {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    skip: SkipArguments,

    #[command(flatten)]
    store: StoreArguments,
}

impl Download {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let store: StoreVisitor = self.store.try_into()?;
        let base = store.base.clone();

        let since = Since::new(self.skip.since, self.skip.since_file)?;

        walk_visitor(
            progress,
            self.client,
            DiscoverConfig::from(self.discover).with_since(since.since),
            self.runner,
            move |source| async move {
                let base = base.clone();
                let visitor = { RetrievingVisitor::new(source.clone(), store) };

                Ok(SkipExistingVisitor {
                    visitor,
                    output: base,
                    since: *since,
                })
            },
        )
        .await?;

        Ok(())
    }
}
