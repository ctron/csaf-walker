use crate::{
    cmd::{DiscoverArguments, FilterArguments},
    common::filter,
};
use csaf_walker::{discover::DiscoveredAdvisory, source::new_source, walker::Walker};
use std::convert::Infallible;
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments},
    progress::Progress,
};

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

impl CommandDefaults for Discover {
    fn progress(&self) -> bool {
        false
    }
}

impl Discover {
    pub async fn run<P: Progress + Clone>(self, progress: P) -> anyhow::Result<()> {
        Walker::new(new_source(self.discover, self.client).await?)
            .with_progress(progress.clone())
            .walk(filter(
                self.filter,
                async |discovered: DiscoveredAdvisory| {
                    progress.println(format!("{}", discovered.url));

                    Ok::<_, Infallible>(())
                },
            ))
            .await?;

        Ok(())
    }
}
