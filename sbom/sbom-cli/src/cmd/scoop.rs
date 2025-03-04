use anyhow::anyhow;
use std::path::{Path, PathBuf};
use walker_common::{
    cli::client::ClientArguments, compression::decompress, progress::Progress,
    scoop::ScooperBuilder,
};
use walker_extras::visitors::{SendArguments, SendVisitor};

/// Walk a local directory (or single file) and send the files to a target without any validation.
#[derive(clap::Args, Debug)]
pub struct Scoop {
    /// Delete processed files
    #[arg(long, conflicts_with = "processed")]
    delete: bool,

    /// Directory to move processed files to.
    #[arg(long)]
    processed: Option<PathBuf>,

    /// Directory to move processed files to.
    #[arg(long)]
    failed: Option<PathBuf>,

    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    send: SendArguments,

    #[command(flatten)]
    source: SourceArguments,
}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Source")]
struct SourceArguments {
    /// Files or directories to upload
    #[arg()]
    source: Vec<PathBuf>,
}

impl Scoop {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        log::debug!("Start processing");

        let scooper = ScooperBuilder {
            sources: self.source.source,
            processed: self.processed,
            failed: self.failed,
            delete: self.delete,
        }
        .build()?;

        let send: SendVisitor = self.send.into_visitor().await?;

        scooper
            .process(progress, async move |path: &Path| {
                let data = tokio::fs::read(&path).await?;
                let name = path
                    .to_str()
                    .ok_or_else(|| anyhow!("Invalid UTF-8 sequence in path"))?;
                let data = decompress(data.into(), name)?;

                send.send_json(&path.to_string_lossy(), data).await?;

                Ok(())
            })
            .await
    }
}
