use crate::{
    cmd::{DiscoverArguments, FilterArguments, VerificationArguments},
    common::walk_visitor,
};
use csaf_walker::{
    discover::AsDiscovered,
    report::{render_to_html, DocumentKey, Duplicates, ReportRenderOption, ReportResult},
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        check::{init_verifying_visitor, CheckError},
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
    },
    visitors::duplicates::DetectDuplicatesVisitor,
};
use reqwest::Url;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::Mutex;
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
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    #[command(flatten)]
    verification: VerificationArguments,

    #[command(flatten)]
    render: RenderOptions,
}

#[derive(clap::Args, Debug)]
pub struct RenderOptions {
    /// Path of the HTML output file
    #[arg(long, default_value = "report.html")]
    pub output: PathBuf,

    /// Make links relative to this URL.
    #[arg(short = 'B', long)]
    pub base_url: Option<Url>,
}

impl Report {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let total = Arc::new(AtomicUsize::default());
        let duplicates: Arc<Mutex<Duplicates>> = Default::default();
        let errors: Arc<Mutex<BTreeMap<DocumentKey, String>>> = Default::default();
        let warnings: Arc<Mutex<BTreeMap<DocumentKey, Vec<CheckError>>>> = Default::default();

        {
            let total = total.clone();
            let duplicates = duplicates.clone();
            let errors = errors.clone();
            let warnings = warnings.clone();

            let visitor = move |advisory: Result<
                VerifiedAdvisory<ValidatedAdvisory, &'static str>,
                VerificationError<ValidationError, ValidatedAdvisory>,
            >| {
                (*total).fetch_add(1, Ordering::Release);

                let errors = errors.clone();
                let warnings = warnings.clone();

                async move {
                    let adv = match advisory {
                        Ok(adv) => adv,
                        Err(err) => {
                            let name = match err.as_discovered().relative_base_and_url() {
                                Some((base, relative)) => DocumentKey {
                                    distribution_url: base.clone(),
                                    url: relative,
                                },
                                None => DocumentKey {
                                    distribution_url: err.url().clone(),
                                    url: Default::default(),
                                },
                            };

                            // let name = err.url().to_string();

                            errors.lock().await.insert(name, err.to_string());
                            return Ok::<_, anyhow::Error>(());
                        }
                    };

                    if !adv.failures.is_empty() {
                        let name = DocumentKey::for_document(&adv);
                        warnings
                            .lock()
                            .await
                            .entry(name)
                            .or_default()
                            .extend(adv.failures.into_values().flatten());
                    }

                    Ok::<_, anyhow::Error>(())
                }
            };
            let visitor = VerifyingVisitor::with_checks(visitor, init_verifying_visitor());
            let visitor = ValidationVisitor::new(visitor).with_options(options);

            walk_visitor(
                progress,
                self.client,
                self.discover,
                self.filter,
                self.runner,
                move |source| async move {
                    let visitor = { RetrievingVisitor::new(source.clone(), visitor) };

                    Ok(DetectDuplicatesVisitor {
                        duplicates,
                        visitor,
                    })
                },
            )
            .await?;
        }

        let total = (*total).load(Ordering::Acquire);

        Self::render(
            self.render,
            ReportResult {
                total,
                duplicates: &*duplicates.lock().await,
                errors: &*errors.lock().await,
                warnings: &*warnings.lock().await,
            },
        )?;

        Ok(())
    }

    fn render(render: RenderOptions, report: ReportResult) -> anyhow::Result<()> {
        let mut out = std::fs::File::create(&render.output)?;

        render_to_html(
            &mut out,
            &report,
            ReportRenderOption {
                output: render.output,
                base_url: render.base_url,
            },
        )?;

        Ok(())
    }
}
