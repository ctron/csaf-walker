mod render;

use crate::{cmd::DiscoverArguments, common::walk_visitor};
use anyhow::anyhow;
use async_trait::async_trait;
use csaf::Csaf;
use csaf_walker::{
    discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor},
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{VerificationError, VerifiedAdvisory, VerifyingVisitor},
};
use reqwest::Url;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
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

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReportResult<'d> {
    pub duplicates: &'d Duplicates,
    pub errors: &'d BTreeMap<String, String>,
    pub warnings: &'d BTreeMap<String, Vec<Cow<'static, str>>>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Duplicates {
    pub duplicates: BTreeMap<String, usize>,
    pub known: HashSet<String>,
}

impl Report {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        let options: ValidationOptions = self.validation.into();

        let duplicates: Arc<Mutex<Duplicates>> = Default::default();
        let errors: Arc<Mutex<BTreeMap<String, String>>> = Default::default();
        let warnings: Arc<Mutex<BTreeMap<String, Vec<Cow<'static, str>>>>> = Default::default();

        {
            let duplicates = duplicates.clone();
            let errors = errors.clone();
            let warnings = warnings.clone();

            let visitor = move |advisory: Result<
                VerifiedAdvisory<ValidatedAdvisory, _>,
                VerificationError<ValidationError, _>,
            >| {
                let errors = errors.clone();
                let warnings = warnings.clone();

                async move {
                    let adv = match advisory {
                        Ok(adv) => adv,
                        Err(err) => {
                            let name = err.url().to_string();
                            errors.lock().unwrap().insert(name, err.to_string());
                            return Ok::<_, anyhow::Error>(());
                        }
                    };

                    if !adv.failures.is_empty() {
                        let name = adv.advisory.url.to_string();
                        warnings
                            .lock()
                            .unwrap()
                            .insert(name, adv.failures.into_values().collect());
                    }

                    Ok::<_, anyhow::Error>(())
                }
            };

            let visitor = VerifyingVisitor::new(visitor);
            let visitor = ValidationVisitor::new(visitor).with_options(options);

            walk_visitor(
                progress,
                self.client,
                self.discover,
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

        Self::render(
            self.render,
            ReportResult {
                duplicates: &duplicates.lock().unwrap(),
                errors: &errors.lock().unwrap(),
                warnings: &warnings.lock().unwrap(),
            },
        )?;

        Ok(())
    }

    fn render(render: RenderOptions, report: ReportResult) -> anyhow::Result<()> {
        let mut out = std::fs::File::create(&render.output)?;
        render::render_to_html(&mut out, &report, &render)?;

        Ok(())
    }

    fn inspect(advisory: Result<ValidatedAdvisory, ValidationError>) -> Result<(), anyhow::Error> {
        let advisory = advisory?;

        serde_json::from_slice::<Csaf>(&advisory.data)
            .map_err(|err| anyhow!("Failed decoding CSAF document: {err}"))?;

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
            if let Some(name) = advisory.url.path().split('/').last() {
                let mut duplicates = self.duplicates.lock().unwrap();
                if !duplicates.known.insert(name.to_string()) {
                    // add or get and increment by one
                    *duplicates.duplicates.entry(name.to_string()).or_default() += 1;
                }
            }
        }

        self.visitor.visit_advisory(context, advisory).await
    }
}
