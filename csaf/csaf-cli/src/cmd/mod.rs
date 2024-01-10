use anyhow::Context;
use csaf_walker::visitors::{filter::FilterConfig, send::SendVisitor, store::StoreVisitor};
use flexible_time::timestamp::StartTimestamp;
use reqwest::Url;
use std::collections::HashSet;
use std::path::PathBuf;
use walker_common::sender::{self, provider::OpenIdTokenProviderConfigArguments, HttpSender};

pub mod discover;
pub mod download;
pub mod parse;
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
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Filters")]
pub struct FilterArguments {
    #[arg(long)]
    /// Distributions to ignore
    pub ignore_distribution: Vec<String>,

    #[arg(long)]
    /// Prefix to ignore
    pub ignore_prefix: Vec<String>,

    #[arg(long)]
    /// Ignore all non-matching prefixes
    pub only_prefix: Vec<String>,
}

impl From<FilterArguments> for FilterConfig {
    fn from(filter: FilterArguments) -> Self {
        Self {
            ignored_distributions: HashSet::from_iter(filter.ignore_distribution),
            ignored_prefixes: filter.ignore_prefix,
            only_prefixes: filter.only_prefix,
        }
    }
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Storage")]
pub struct StoreArguments {
    /// Disable the use of extended attributes, e.g. for etag information.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long)]
    pub no_xattrs: bool,

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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            no_xattrs: value.no_xattrs,
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
