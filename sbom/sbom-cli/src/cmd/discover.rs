use crate::{cmd::DiscoverArguments, common::new_source};
use sbom_walker::{discover::DiscoveredSbom, walker::Walker};
use std::convert::Infallible;
use walker_common::cli::client::ClientArguments;
use walker_common::progress::Progress;

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
            .walk(|discovered: DiscoveredSbom| async move {
                println!(
                    "{} ({})",
                    discovered.url,
                    humantime::format_rfc3339(discovered.modified),
                );

                Ok::<_, Infallible>(())
            })
            .await?;

        Ok(())
    }
}
