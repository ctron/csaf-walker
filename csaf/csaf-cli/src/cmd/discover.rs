use crate::{
    cmd::{DiscoverArguments, FilterArguments},
    common::{filter, new_source},
};
use csaf_walker::{discover::DiscoveredAdvisory, walker::Walker};
use std::convert::Infallible;
use walker_common::{cli::client::ClientArguments, progress::Progress};

/// Discover advisories, just lists the URLs.
#[derive(clap::Args, Debug)]
pub struct Discover {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,
}

impl Discover {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        Walker::new(new_source(self.discover, self.client).await?)
            .with_progress(progress)
            .walk(filter(
                self.filter,
                |discovered: DiscoveredAdvisory| async move {
                    println!("{}", discovered.url);

                    Ok::<_, Infallible>(())
                },
            ))
            .await?;

        Ok(())
    }
}
