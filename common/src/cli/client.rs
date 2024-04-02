use crate::fetcher::{Fetcher, FetcherOptions};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Client")]
pub struct ClientArguments {
    /// Per-request HTTP timeout, in humantime duration format.
    #[arg(short, long, default_value = "5s")]
    pub timeout: humantime::Duration,

    /// Per-request retries count
    #[arg(short, long, default_value = "5")]
    pub retries: usize,
}

impl ClientArguments {
    /// Create a new [`Fetcher`] from arguments.
    pub async fn new_fetcher(self) -> Result<Fetcher, anyhow::Error> {
        Fetcher::new(FetcherOptions {
            timeout: self.timeout.into(),
            retries: self.retries,
        })
        .await
    }
}
