mod cmd;
mod common;
mod utils;

use clap::Parser;
use cmd::{discover::Discover, download::Download, scan::Scan, sync::Sync};
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
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Download(Download),
    Scan(Scan),
    Discover(Discover),
    Sync(Sync),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<()> {
        match self {
            Command::Download(download) => download.run().await,
            Command::Scan(scan) => scan.run().await,
            Command::Discover(discover) => discover.run().await,
            Command::Sync(sync) => sync.run().await,
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

        // not init the logger

        builder.init();

        let time = MeasureTime::new();
        self.command.run().await?;
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
