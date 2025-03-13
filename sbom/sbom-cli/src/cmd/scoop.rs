use bytes::Bytes;
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments},
    compression::decompress,
    progress::Progress,
    scoop::{ScooperBuilder, Source},
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
    processed: Option<String>,

    /// Directory to move processed files to.
    #[arg(long)]
    failed: Option<String>,

    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    send: SendArguments,

    #[command(flatten)]
    source: SourceArguments,
}

impl CommandDefaults for Scoop {}

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Source")]
struct SourceArguments {
    /// Files or directories to upload
    #[arg()]
    source: Vec<String>,
}

impl Scoop {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        log::debug!("Start processing");

        let scooper = ScooperBuilder {
            sources: self
                .source
                .source
                .into_iter()
                .map(|s| Source::try_from(s.as_str()))
                .collect::<Result<_, _>>()?,
            processed: self.processed,
            failed: self.failed,
            delete: self.delete,
        }
        .build()
        .await?;

        let send: SendVisitor = self.send.into_visitor().await?;

        scooper
            .process(progress, async move |name: &str, data: Bytes| {
                let data = decompress(data, name)?;
                send.send_json(name, data).await?;
                Ok(())
            })
            .await
    }
}
