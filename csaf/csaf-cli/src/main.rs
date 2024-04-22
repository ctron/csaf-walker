mod cmd;
mod common;

use clap::Parser;
use cmd::{
    discover::Discover, download::Download, metadata::Metadata, parse::Parse, report::Report,
    scan::Scan, send::Send, sync::Sync,
};
use std::process::ExitCode;
use walker_common::{cli::log::Logging, progress::Progress, utils::measure::MeasureTime};

#[derive(Debug, Parser)]
#[command(version, about = "CSAF Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    logging: Logging,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
enum Command {
    Parse(Parse),
    Download(Download),
    Scan(Scan),
    Discover(Discover),
    Sync(Sync),
    Report(Report),
    Send(Send),
    Metadata(Metadata),
}

impl Command {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        match self {
            Command::Parse(cmd) => cmd.run(progress).await,
            Command::Download(cmd) => cmd.run(progress).await,
            Command::Scan(cmd) => cmd.run(progress).await,
            Command::Discover(cmd) => cmd.run(progress).await,
            Command::Sync(cmd) => cmd.run(progress).await,
            Command::Report(cmd) => cmd.run(progress).await,
            Command::Send(cmd) => cmd.run(progress).await,
            Command::Metadata(cmd) => cmd.run().await,
        }
    }
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let progress = self.logging.init(&["csaf", "csaf_walker"]);

        // run

        log::debug!("Setup complete, start processing");

        let time = MeasureTime::new();
        self.command.run(progress).await?;
        drop(time);

        Ok(())
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = Cli::parse().run().await {
        log::error!("Failed to execute: {err}");
        for (n, cause) in err.chain().enumerate().skip(1) {
            log::info!("  {n}: {cause}");
        }
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
