mod render;

use crate::{cmd::DiscoverArguments, common::walk_visitor};
use reqwest::Url;
use sbom_walker::discover::DiscoveredSbom;
use sbom_walker::retrieve::RetrievedSbom;
use sbom_walker::{
    model::sbom::ParseAnyError,
    retrieve::RetrievingVisitor,
    validation::{ValidatedSbom, ValidationError, ValidationVisitor},
    Sbom,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::task;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    compression::decompress,
    progress::Progress,
    validate::ValidationOptions,
};

#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Parse(#[from] ParseAnyError),
    #[error(transparent)]
    Decompression(anyhow::Error),
}

/// Analyze (and report) the state of the data.
#[derive(clap::Args, Debug)]
pub struct Report {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    render: RenderOptions,
}

#[derive(clap::Args, Debug)]
pub struct RenderOptions {
    /// Path of the HTML output file
    #[arg(long, default_value = "report.html")]
    output: PathBuf,

    /// Make links relative to this URL.
    #[arg(short = 'B', long)]
    base_url: Option<Url>,
}

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub errors: &'d BTreeMap<String, SbomError>,
    pub total: usize,
}

impl Report {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let errors: Arc<Mutex<BTreeMap<String, SbomError>>> = Default::default();
        let total: Arc<AtomicUsize> = Default::default();

        {
            let errors = errors.clone();
            let total = total.clone();
            walk_visitor(
                progress,
                self.client,
                self.discover,
                self.runner,
                |source| async move {
                    Ok(RetrievingVisitor::new(
                        source.clone(),
                        ValidationVisitor::new(
                            move |sbom: Result<ValidatedSbom, ValidationError>| {
                                let errors = errors.clone();
                                total.fetch_add(1, Ordering::SeqCst);
                                async move {
                                    let name = match &sbom {
                                        Ok(sbom) => sbom.url.to_string(),
                                        Err(sbom) => sbom.url().to_string(),
                                    };
                                    if let Err(err) = Self::inspect(sbom).await {
                                        errors.lock().unwrap().insert(name, err);
                                    }

                                    Ok::<_, anyhow::Error>(())
                                }
                            },
                        )
                        .with_options(options),
                    ))
                },
            )
            .await?;
        }

        Self::render(
            self.render,
            ReportResult {
                errors: &errors.lock().unwrap(),
                total: total.load(Ordering::SeqCst),
            },
        )?;

        Ok(())
    }

    fn render(render: RenderOptions, report: ReportResult) -> anyhow::Result<()> {
        let mut out = std::fs::File::create(&render.output)?;
        render::render_to_html(&mut out, &report, &render)?;

        Ok(())
    }

    async fn inspect(sbom: Result<ValidatedSbom, ValidationError>) -> Result<(), SbomError> {
        let sbom = sbom?;
        let ValidatedSbom {
            retrieved:
                RetrievedSbom {
                    data,
                    discovered: DiscoveredSbom { url, .. },
                    ..
                },
        } = sbom;

        let data = task::spawn_blocking(move || decompress(data, url.path()))
            .await
            .expect("unable to spawn decompression")
            .map_err(SbomError::Decompression)?;

        let _ = Sbom::try_parse_any(&data)?;

        Ok(())
    }
}
