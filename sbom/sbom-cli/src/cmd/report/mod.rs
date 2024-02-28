use crate::{cmd::DiscoverArguments, common::walk_visitor};
use reqwest::Url;
use sbom_walker::report::render::{render_to_html, ReportRenderOption};
use sbom_walker::report::{inspect, ReportResult, SbomError};
use sbom_walker::{
    retrieve::RetrievingVisitor,
    validation::{ValidatedSbom, ValidationError, ValidationVisitor},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    utils::url::Urlify,
    validate::ValidationOptions,
};

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

impl Report {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let total: Arc<AtomicUsize> = Default::default();
        let errors: Arc<Mutex<BTreeMap<String, SbomError>>> = Default::default();

        {
            let total = total.clone();
            let errors = errors.clone();
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
                                    if let Err(err) = inspect(sbom).await {
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
        render_to_html(
            &mut out,
            &report,
            &ReportRenderOption {
                output: render.output,
                base_url: render.base_url,
            },
        )?;

        Ok(())
    }
}
