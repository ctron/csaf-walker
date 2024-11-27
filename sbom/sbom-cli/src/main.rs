mod cmd;
mod common;
mod inspect;

use crate::cmd::{
    discover::Discover, download::Download, inspect::Inspect, report::Report, scan::Scan,
    scoop::Scoop, send::Send, sync::Sync,
};
use clap::Parser;
use std::process::ExitCode;
use walker_common::{cli::log::Logging, progress::Progress, utils::measure::MeasureTime};

#[derive(Debug, Parser)]
#[command(version, about = "SBOM Tool", author, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    logging: Logging,
}

#[allow(clippy::large_enum_variant)]
#[derive(clap::Subcommand, Debug)]
enum Command {
    Discover(Discover),
    Download(Download),
    Sync(Sync),
    Scan(Scan),
    Report(Report),
    Send(Send),
    Scoop(Scoop),
    Inspect(Inspect),
}

impl Command {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        match self {
            Command::Discover(cmd) => cmd.run(progress).await,
            Command::Download(cmd) => cmd.run(progress).await,
            Command::Sync(cmd) => cmd.run(progress).await,
            Command::Scan(cmd) => cmd.run(progress).await,
            Command::Report(cmd) => cmd.run(progress).await,
            Command::Send(cmd) => cmd.run(progress).await,
            Command::Scoop(cmd) => cmd.run(progress).await,
            Command::Inspect(cmd) => cmd.run(progress).await,
        }
    }
}
impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let progress = self.logging.init(&["sbom", "sbom_walker"]);

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
