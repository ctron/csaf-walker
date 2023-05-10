use crate::cmd::{ClientArguments, DiscoverArguments};
use crate::common::new_source;
use csaf_walker::discover::DiscoveredAdvisory;
use csaf_walker::progress::Progress;
use csaf_walker::walker::Walker;
use std::convert::Infallible;

/// Discover advisories, just lists the URLs.
#[derive(clap::Args, Debug)]
pub struct Discover {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,
}

impl Discover {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        Walker::new(new_source(self.discover, self.client).await?)
            .with_progress(progress)
            .walk(|discovered: DiscoveredAdvisory| async move {
                println!("{}", discovered.url);

                Ok::<_, Infallible>(())
            })
            .await?;

        Ok(())
    }
}
