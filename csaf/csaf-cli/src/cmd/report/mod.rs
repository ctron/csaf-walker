mod render;
use crate::{
    cmd::{DiscoverArguments, FilterArguments},
    common::walk_visitor,
};
use async_trait::async_trait;
use csaf_walker::{
    discover::{AsDiscovered, DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor},
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        check::{init_verifying_visitor, CheckError},
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
    },
};
use reqwest::Url;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
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
    filter: FilterArguments,

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

    /// Generate report in JSON format
    #[arg(long, default_value = "report.json")]
    json_output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ReportResult<'d> {
    pub total: usize,
    pub duplicates: &'d Duplicates,
    pub errors: &'d BTreeMap<DocumentKey, String>,
    pub warnings: &'d BTreeMap<DocumentKey, Vec<Cow<'static, str>>>,
}

#[derive(Clone, Debug, Default)]
pub struct Duplicates {
    pub duplicates: BTreeMap<DocumentKey, usize>,
    pub known: HashSet<DocumentKey>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct DocumentKey {
    /// the URL to the distribution folder
    pub distribution_url: Url,
    /// the URL to the document, relative to the `distribution_url`.
    pub url: String,
}

impl DocumentKey {
    pub fn for_document(advisory: &DiscoveredAdvisory) -> Self {
        Self {
            distribution_url: advisory.distribution.directory_url.clone(),
            url: advisory.possibly_relative_url(),
        }
    }
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

                            errors.lock().unwrap().insert(name, err.to_string());
                            return Ok::<_, anyhow::Error>(());
                        }
                    };

                    if !adv.failures.is_empty() {
                        let name = DocumentKey::for_document(&adv);
                        warnings
                            .lock()
                            .unwrap()
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
                duplicates: &duplicates.lock().unwrap(),
                errors: &errors.lock().unwrap(),
                warnings: &warnings.lock().unwrap(),
            },
        )?;

        Ok(())
    }

    fn render(render: RenderOptions, report: ReportResult) -> anyhow::Result<()> {
        if let Some(json_output) = &render.json_output {
            let mut out = std::fs::File::create(json_output)?;
            render::render_to_json(&mut out, &report)?;
        }
        let mut out = std::fs::File::create(&render.output)?;
        render::render_to_html(&mut out, &report, &render)?;

        Ok(())
    }
}

pub struct DetectDuplicatesVisitor<D: DiscoveredVisitor> {
    pub visitor: D,
    pub duplicates: Arc<Mutex<Duplicates>>,
}

#[async_trait(?Send)]
impl<V: DiscoveredVisitor> DiscoveredVisitor for DetectDuplicatesVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        {
            let key = DocumentKey::for_document(&advisory);

            let mut duplicates = self.duplicates.lock().unwrap();
            if !duplicates.known.insert(key.clone()) {
                // add or get and increment by one
                *duplicates.duplicates.entry(key).or_default() += 1;
            }
        }

        self.visitor.visit_advisory(context, advisory).await
    }
}
