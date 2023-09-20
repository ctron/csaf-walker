mod render;

use crate::{
    cmd::{ClientArguments, DiscoverArguments, RunnerArguments, ValidationArguments},
    common::walk_visitor,
};
use anyhow::anyhow;
use async_trait::async_trait;
use csaf::Csaf;
use csaf_walker::{
    discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor},
    progress::Progress,
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor},
};
use reqwest::Url;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
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

        {
            let duplicates = duplicates.clone();
            let errors = errors.clone();
            walk_visitor(
                progress,
                self.client,
                self.discover,
                self.runner,
                move |source| async move {
                    let visitor = {
                        RetrievingVisitor::new(
                            source.clone(),
                            ValidationVisitor::new(
                                move |advisory: Result<ValidatedAdvisory, ValidationError>| {
                                    let errors = errors.clone();
                                    async move {
                                        let name = match &advisory {
                                            Ok(adv) => adv.url.to_string(),
                                            Err(adv) => adv.url().to_string(),
                                        };
                                        if let Err(err) = Self::inspect(advisory) {
                                            errors.lock().unwrap().insert(name, err.to_string());
                                        }

                                        Ok::<_, anyhow::Error>(())
                                    }
                                },
                            )
                            .with_options(options),
                        )
                    };

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
