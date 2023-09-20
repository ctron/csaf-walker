use crate::cmd::StoreArguments;
use crate::{
    cmd::{DiscoverArguments, RunnerArguments, SkipArguments},
    common::{walk_visitor, DiscoverConfig},
};
use sbom_walker::retrieve::RetrievingVisitor;
use sbom_walker::visitors::skip::SkipExistingVisitor;
use sbom_walker::visitors::store::StoreVisitor;
use walker_common::cli::client::ClientArguments;
use walker_common::cli::validation::ValidationArguments;
use walker_common::{progress::Progress, since::Since};

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
