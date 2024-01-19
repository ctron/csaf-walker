use anyhow::Context;
use flexible_time::timestamp::StartTimestamp;
use reqwest::Url;
use sbom_walker::visitors::store::StoreVisitor;
use std::path::PathBuf;
use walker_common::sender::{self, provider::OpenIdTokenProviderConfigArguments, HttpSender};
use walker_extras::visitors::SendVisitor;

pub mod discover;
pub mod download;
pub mod report;
pub mod scan;
pub mod send;
pub mod sync;

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Discovery")]
pub struct DiscoverArguments {
    /// Source to scan from, will be suffixed with "/.well-known/csaf/provider-metadata.json" unless "--full" is used.
    pub source: String,
    #[arg(long)]
    /// Treat the "source" as a full URL to the metadata.
    pub full: bool,
    #[arg(short = 'k', long = "key")]
    /// URLs to keys which should be used for validation. The fragment part of a key can be used as fingerprint.
    pub keys: Vec<Url>,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Storage")]
pub struct StoreArguments {
    /// Disable applying the modification timestamp to the downloaded file.
    #[arg(long)]
    pub no_timestamps: bool,

    /// Output path, defaults to the local directory.
    #[arg(short, long)]
    pub data: Option<PathBuf>,
}

impl TryFrom<StoreArguments> for StoreVisitor {
    type Error = anyhow::Error;

    fn try_from(value: StoreArguments) -> Result<Self, Self::Error> {
        let base = match value.data {
            Some(base) => base,
            None => std::env::current_dir().context("Get current working directory")?,
        };

        Ok(Self {
            no_timestamps: value.no_timestamps,
            base,
        })
    }
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Sending")]
pub struct SendArguments {
    /// Target to send to
    pub target: Url,

    /// Sender connect timeout
    #[arg(id = "sender-connect-timeout", long, default_value = "15s")]
    pub connect_timeout: humantime::Duration,

    /// Sender request timeout
    #[arg(id = "sender-timeout", long, default_value = "5m")]
    pub timeout: humantime::Duration,

    #[command(flatten)]
    pub oidc: OpenIdTokenProviderConfigArguments,
}

impl SendArguments {
    pub async fn into_visitor(self) -> Result<SendVisitor, anyhow::Error> {
        let provider = self.oidc.into_provider().await?;
        let sender = HttpSender::new(
            provider,
            sender::Options {
                connect_timeout: Some(self.connect_timeout.into()),
                timeout: Some(self.timeout.into()),
            },
        )
        .await?;

        Ok(SendVisitor {
            url: self.target,
            sender,
        })
    }
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Skipping")]
pub struct SkipArguments {
    /// Provide a timestamp since when files will be considered changed.
    #[arg(short, long)]
    pub since: Option<StartTimestamp>,

    /// A file to read/store the last sync timestamp to at the end of a successful run.
    #[arg(short = 'S', long)]
    pub since_file: Option<PathBuf>,

    /// A delta to add to the value loaded from the since state file.
    #[arg(long)]
    pub since_file_offset: Option<humantime::Duration>,
}
