use crate::cmd::{ClientArguments, DiscoverArguments};
use crate::common::new_fetcher;
use csaf_walker::discover::DiscoveredAdvisory;
use csaf_walker::source::HttpSource;
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
    pub async fn run(self) -> anyhow::Result<()> {
        let fetcher = new_fetcher(self.client).await?;

        Walker::new(HttpSource {
            url: self.discover.source,
            fetcher,
        })
        .walk(|discovered: DiscoveredAdvisory| async move {
            println!("{}", discovered.url);

            Ok::<_, Infallible>(())
        })
        .await?;

        Ok(())
    }
}
