use anyhow::Context;
use csaf_walker::visitors::store::StoreVisitor;
use flexible_time::timestamp::StartTimestamp;
use std::path::PathBuf;

pub mod discover;
pub mod download;
pub mod report;
pub mod scan;
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