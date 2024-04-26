use crate::cmd::DiscoverArguments;
use sbom_walker::{discover::DiscoveredSbom, source::new_source, walker::Walker};
use std::convert::Infallible;
use walker_common::{cli::client::ClientArguments, progress::Progress};

/// Discover SBOMs, just lists the URLs.
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
