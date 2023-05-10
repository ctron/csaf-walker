use crate::cmd::{ClientArguments, DiscoverArguments, StoreArguments, ValidationArguments};
use crate::common::walk_visitor;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{ValidationOptions, ValidationVisitor};
use csaf_walker::visitors::skip::SkipExistingVisitor;
use csaf_walker::visitors::store::StoreVisitor;

/// Sync only what changed, and don't validate.
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
}

impl Sync {
    pub async fn run(self) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();
        let store: StoreVisitor = self.store.try_into()?;
        let base = store.base.clone();

        walk_visitor(self.client, self.discover, move |source| async move {
            let base = base.clone();
            let visitor = {
                RetrievingVisitor::new(
                    source.clone(),
                    ValidationVisitor::new(store).with_options(options),
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
