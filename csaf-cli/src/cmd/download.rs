use crate::cmd::{ClientArguments, DiscoverArguments, StoreArguments, ValidationArguments};
use crate::common::walk_visitor;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::visitors::skip::SkipExistingVisitor;
use csaf_walker::visitors::store::StoreVisitor;

/// Like sync, but doesn't validate.
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
}

impl Download {
    pub async fn run(self) -> anyhow::Result<()> {
        let store: StoreVisitor = self.store.try_into()?;
        let base = store.base.clone();

        walk_visitor(self.client, self.discover, move |source| async move {
            let base = base.clone();
            let visitor = { RetrievingVisitor::new(source.clone(), store) };

            Ok(SkipExistingVisitor {
                visitor,
                output: base,
            })
        })
        .await?;

        Ok(())
    }
}
