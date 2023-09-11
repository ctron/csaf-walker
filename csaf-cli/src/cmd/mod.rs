use anyhow::Context;
use csaf_walker::{validation::ValidationOptions, visitors::store::StoreVisitor};
use flexible_time::timestamp::StartTimestamp;
use std::path::PathBuf;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};

pub mod discover;
pub mod download;
pub mod report;
pub mod scan;
pub mod sync;

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Client")]
pub struct ClientArguments {
    /// Per-request HTTP timeout, in humantime duration format.
    #[arg(short, long, default_value = "5s")]
    pub timeout: humantime::Duration,

    /// Per-request retries count
    #[arg(short, long, default_value = "50")]
    pub retries: usize,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Discovery")]
pub struct DiscoverArguments {
    /// Source to scan from, must be a URL pointing to the 'provider-metadata.json' file or path to a stored set of files.
    pub source: String,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Runner")]
pub struct RunnerArguments {
    /// Number of workers, too many parallel requests might make you violate request rates. NOTE: A number of zero will spawn an unlimited amount of workers.
    #[arg(short, long, default_value = "1")]
    pub workers: usize,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Validation")]
pub struct ValidationArguments {
    /// OpenPGP policy date.
    #[arg(long)]
    policy_date: Option<humantime::Timestamp>,

    /// Enable OpenPGP v3 signatures. Conflicts with 'policy_date'.
    #[arg(short = '3', long = "v3-signatures", conflicts_with = "policy_date")]
    v3_signatures: bool,
}

impl From<ValidationArguments> for ValidationOptions {
    fn from(value: ValidationArguments) -> Self {
        let validation_date: Option<SystemTime> = match (value.policy_date, value.v3_signatures) {
            (_, true) => Some(SystemTime::from(
                Date::from_calendar_date(2007, Month::January, 1)
                    .unwrap()
                    .midnight()
                    .assume_offset(UtcOffset::UTC),
            )),
            (Some(date), _) => Some(date.into()),
            _ => None,
        };

        log::debug!("Policy date: {validation_date:?}");

        Self { validation_date }
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
