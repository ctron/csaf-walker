use flexible_time::timestamp::StartTimestamp;
use std::path::PathBuf;

pub mod discover;

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
#[command(next_help_heading = "Runner")]
pub struct RunnerArguments {
    /// Number of workers, too many parallel requests might make you violate request rates. NOTE: A number of zero will spawn an unlimited amount of workers.
    #[arg(short, long, default_value = "1")]
    pub workers: usize,
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
