mod cmd;
mod common;

use crate::cmd::{discover::Discover, download::Download};
use clap::Parser;
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use log::LevelFilter;
use std::io::Write;
use std::process::ExitCode;
use walker_common::{
    progress::{indicatif::MultiIndicatif, NoProgress, Progress},
    utils::measure::MeasureTime,
};

#[derive(Debug, Parser)]
#[command(version, about = "SBOM Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Be quiet. Conflicts with 'verbose'.
    #[arg(short, long, conflicts_with = "verbose", global = true)]
    quiet: bool,

    /// Be more verbose. May be repeated multiple times to increase verbosity.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Add timestamps to the output messages
    #[arg(long, global = true)]
    log_timestamps: bool,

    /// Disable progress bar
    #[arg(long, global = true)]
    no_progress: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Discover(Discover),
    Download(Download),
}

impl Command {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        match self {
            Command::Discover(cmd) => cmd.run(progress).await,
            Command::Download(cmd) => cmd.run(progress).await,
        }
    }
}
impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        // init logging

        let mut builder = env_logger::builder();

        // remove timestamps

        if !self.log_timestamps {
            builder.format(|buf, record| writeln!(buf, "{}", record.args()));
        }

        // log level

        match (self.quiet, self.verbose) {
            (true, _) => builder.filter_level(LevelFilter::Off),
            (_, 0) => builder
                .filter_level(LevelFilter::Warn)
                .filter_module("csaf", LevelFilter::Info),
            (_, 1) => builder
                .filter_level(LevelFilter::Warn)
                .filter_module("csaf", LevelFilter::Info)
                .filter_module("csaf_walker", LevelFilter::Info),
            (_, 2) => builder
                .filter_level(LevelFilter::Warn)
                .filter_module("csaf", LevelFilter::Debug)
                .filter_module("csaf_walker", LevelFilter::Debug),
            (_, 3) => builder
                .filter_level(LevelFilter::Info)
                .filter_module("csaf", LevelFilter::Debug)
                .filter_module("csaf_walker", LevelFilter::Debug),
            (_, 4) => builder.filter_level(LevelFilter::Debug),
            (_, _) => builder.filter_level(LevelFilter::Trace),
        };

        // init the progress meter

        let progress = match self.quiet | self.no_progress {
            true => {
                builder.init();
                Progress::new(NoProgress)
            }
            false => {
                let logger = builder.build();
                let max_level = logger.filter();
                let multi = MultiProgress::new();
                let log = LogWrapper::new(multi.clone(), logger);
                // NOTE: LogWrapper::try_init is buggy and messes up the log levels
                log::set_boxed_logger(Box::new(log)).unwrap();
                log::set_max_level(max_level);

                Progress::new(MultiIndicatif(multi))
            }
        };

        // run

        log::debug!("Setup complete, start processing");

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
