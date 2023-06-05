mod cmd;
mod common;
mod progress;
mod utils;

use crate::progress::Indicatif;
use clap::Parser;
use cmd::{discover::Discover, download::Download, report::Report, scan::Scan, sync::Sync};
use csaf_walker::progress::{NoProgress, Progress};
use log::LevelFilter;
use std::io::Write;
use std::process::ExitCode;
use utils::MeasureTime;

#[derive(Debug, Parser)]
#[command(version, about = "CSAF Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Be quiet. Conflicts with 'verbose'.
    #[arg(short, long, conflicts_with = "verbose", global = true)]
    quiet: bool,

    /// Be more verbose. May be repeated multiple times to increase verbosity.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Disable progress bar
    #[arg(long, global = true)]
    no_progress: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Download(Download),
    Scan(Scan),
    Discover(Discover),
    Sync(Sync),
    Report(Report),
}

impl Command {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        match self {
            Command::Download(cmd) => cmd.run(progress).await,
            Command::Scan(cmd) => cmd.run().await,
            Command::Discover(cmd) => cmd.run(progress).await,
            Command::Sync(cmd) => cmd.run(progress).await,
            Command::Report(cmd) => cmd.run(progress).await,
        }
    }
}
impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        // init logging

        let mut builder = env_logger::builder();

        // remove timestamps

        builder.format(|buf, record| writeln!(buf, "{}", record.args()));

        match (self.quiet, self.verbose) {
            (true, _) => builder.filter_level(LevelFilter::Off),
            (_, 0) => builder
                .filter_level(LevelFilter::Warn)
                .filter_module("csaf_cli", LevelFilter::Info),
            (_, 1) => builder.filter_level(LevelFilter::Info),
            (_, 2) => builder.filter_level(LevelFilter::Debug),
            (_, _) => builder.filter_level(LevelFilter::Trace),
        };

        let progress = match (self.quiet | self.no_progress, self.verbose) {
            (false, 0) => Progress::new(Indicatif),
            _ => Progress::new(NoProgress),
        };

        // not init the logger

        builder.init();

        let time = MeasureTime::new(self.quiet);
        self.command.run(progress).await?;
        drop(time);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = Cli::parse().run().await {
        eprintln!("{err}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
