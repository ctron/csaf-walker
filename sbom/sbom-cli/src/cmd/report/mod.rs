mod check;
mod render;

use crate::{cmd::DiscoverArguments, common::walk_visitor};
use parking_lot::Mutex;
use reqwest::Url;
use sbom_walker::{
    discover::DiscoveredSbom,
    model::sbom::ParseAnyError,
    retrieve::{RetrievedSbom, RetrievingVisitor},
    validation::{ValidatedSbom, ValidationError, ValidationVisitor},
    Sbom,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::task;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    compression::decompress,
    progress::Progress,
    utils::url::Urlify,
    validate::ValidationOptions,
};

#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Parse(#[from] ParseAnyError),
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
    pub errors: &'d BTreeMap<String, Vec<String>>,
    pub total: usize,
}

pub trait ReportSink {
    fn error(&self, msg: String);
}

impl ReportSink for (String, Arc<Mutex<BTreeMap<String, Vec<String>>>>) {
    fn error(&self, msg: String) {
        self.1.lock().entry(self.0.clone()).or_default().push(msg);
    }
}

impl Report {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let total: Arc<AtomicUsize> = Default::default();
        let errors: Arc<Mutex<BTreeMap<String, Vec<String>>>> = Default::default();

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

                                    task::spawn_blocking(move || {
                                        Self::inspect(&(name, errors), sbom);
                                    })
                                    .await
                                    .expect("unable to spawn inspection");

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
                errors: &errors.lock(),
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

    fn inspect(report: &dyn ReportSink, sbom: Result<ValidatedSbom, ValidationError>) {
        let sbom = match sbom {
            Ok(sbom) => sbom,
            Err(err) => {
                report.error(format!("Failed to retrieve: {err}"));
                return;
            }
        };

        let ValidatedSbom {
            retrieved:
                RetrievedSbom {
                    data,
                    discovered: DiscoveredSbom { url, .. },
                    ..
                },
        } = sbom;

        let data = decompress(data, url.path());

        let data = match data {
            Ok(data) => data,
            Err(err) => {
                report.error(format!("Failed to decode file: {err}"));
                return;
            }
        };

        let mut value = match serde_json::from_slice(&data) {
            Ok(value) => value,
            Err(err) => {
                report.error(format!(
                    "Failed to parse file as JSON: {err} (currently only JSON files are supported)"
                ));
                return;
            }
        };

        if Sbom::is_spdx_json(&value).is_ok() {
            let (new, _) = fix_license(report, value);
            value = new;
        }

        let sbom = match Sbom::try_parse_any_json(value) {
            Ok(sbom) => sbom,
            Err(err) => {
                report.error(format!("Failed to parse file: {err}"));
                return;
            }
        };

        check::all(report, sbom);
    }
}

/// Check the document for invalid SPDX license expressions and replace them with `NOASSERTION`.
pub fn fix_license(report: &dyn ReportSink, mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    report.error(format!("Faulty SPDX license expression: {err}"));
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;
                }
            }
        }
    }

    (json, changed)
}
