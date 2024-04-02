use crate::common::{new_source, DiscoverConfig};
use colored_json::write_colored_json;
use csaf_walker::metadata::MetadataRetriever;
use csaf_walker::{metadata, model::metadata::ProviderMetadata, source::Source};
use std::fmt::Display;
use std::io::stdout;
use walker_common::cli::client::ClientArguments;

/// Discover advisories, just lists the URLs.
#[derive(clap::Args, Debug)]
pub struct Metadata {
    #[command(flatten)]
    client: ClientArguments,

    /// The source to check for metadata
    source: String,

    /// Try and show all approaches
    #[arg(short = 'A', long)]
    all: bool,
}

impl Metadata {
    pub async fn run(self) -> anyhow::Result<()> {
        #[cfg(windows)]
        let enabled = colored_json::enable_ansi_support();

        if self.all {
            self.all().await
        } else {
            self.default().await
        }
    }

    async fn all(self) -> anyhow::Result<()> {
        let fetcher = self.client.new_fetcher().await?;
        let metadata = MetadataRetriever::new(self.source);

        Self::show_approach("Direct URL", &metadata.approach_full_url(&fetcher).await)?;
        Self::show_approach("Well-known", &metadata.approach_well_known(&fetcher).await)?;

        Self::show_approach(
            "/.well-known/security.txt",
            &metadata
                .approach_security_txt(&fetcher, "/.well-known/security.txt")
                .await,
        )?;
        Self::show_approach(
            "/security.txt",
            &metadata
                .approach_security_txt(&fetcher, "/security.txt")
                .await,
        )?;
        Self::show_approach("DNS", &metadata.approach_dns(&fetcher).await)?;

        Ok(())
    }

    async fn default(self) -> anyhow::Result<()> {
        let source = new_source(
            DiscoverConfig {
                since: None,
                source: self.source,
            },
            self.client,
        )
        .await?;

        let metadata = source.load_metadata().await?;
        Self::show_metadata(&metadata)?;

        Ok(())
    }

    fn show_metadata(metadata: &ProviderMetadata) -> anyhow::Result<()> {
        write_colored_json(&metadata, &mut stdout().lock())?;

        Ok(())
    }

    fn show_approach(
        name: impl Display,
        metadata: &Result<Option<ProviderMetadata>, metadata::Error>,
    ) -> anyhow::Result<()> {
        match metadata {
            Ok(Some(metadata)) => {
                println!("{name}:");
                write_colored_json(&metadata, &mut stdout().lock())?;
                println!();
                println!();
            }
            Ok(None) => {
                println!("{name}: <<none>>");
                println!();
            }
            Err(err) => {
                println!("{name} (Err): {err}");
                println!();
            }
        }

        Ok(())
    }
}
