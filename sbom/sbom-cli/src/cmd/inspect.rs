use crate::inspect::inspect_validated;
use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::Mutex;
use reqwest::Url;
use sbom_walker::{discover::DiscoveredSbom, retrieve::RetrievedSbom, validation::ValidatedSbom};
use std::{collections::BTreeMap, path::absolute, sync::Arc, time::SystemTime};
use walker_common::{
    cli::{CommandDefaults, client::ClientArguments, validation::ValidationArguments},
    fetcher::Fetcher,
    progress::{Progress, ProgressBar},
};

/// Inspect SBOMs
#[derive(clap::Args, Debug)]
pub struct Inspect {
    /// The documents to inspect. Files or URLs.
    #[arg()]
    sources: Vec<String>,

    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    validation: ValidationArguments,
}

impl CommandDefaults for Inspect {}

impl Inspect {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        let fetcher = self.client.new_fetcher().await?;

        let messages = Arc::new(Mutex::new(BTreeMap::new()));

        let mut progress = progress.start(self.sources.len());

        for source in self.sources {
            log::info!("Inspecting: {source}");
            Self::inspect(&fetcher, messages.clone(), &source).await?;
            progress.tick().await;
        }
        progress.finish().await;

        let messages = messages.lock();
        for (source, messages) in &*messages {
            println!("{source}:");
            for message in messages {
                println!("\t{message}");
            }
        }

        match messages.len() {
            0 => {
                println!("All sources are ok");
                Ok(())
            }
            1 => Err(anyhow!("1 source had errors")),
            n => Err(anyhow!("{n} sources had errors")),
        }
    }

    async fn inspect(
        fetcher: &Fetcher,
        messages: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
        source: &str,
    ) -> anyhow::Result<()> {
        let (data, url) = if source.starts_with("http://") || source.starts_with("https://") {
            log::debug!("Fetching remote");
            let url = Url::parse(source)?;
            (fetcher.fetch::<Bytes>(url.clone()).await?, url)
        } else {
            log::debug!("Fetching local");
            let path = absolute(source)?;
            log::debug!("Fetching local: {path:?}");
            let url = Url::from_file_path(&path)
                .map_err(|()| anyhow!("Failed to convert file to URL"))?;
            (tokio::fs::read(path).await?.into(), url)
        };

        log::info!("{} bytes of data", data.len());

        inspect_validated(
            &(source, messages),
            ValidatedSbom {
                retrieved: RetrievedSbom {
                    discovered: DiscoveredSbom {
                        url,
                        modified: SystemTime::now(),
                    },
                    data,
                    signature: None,
                    sha256: None,
                    sha512: None,
                    metadata: Default::default(),
                },
            },
        );

        Ok(())
    }
}
