mod render;

use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
use crate::common::walk_visitor;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use csaf_walker::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use csaf_walker::model::metadata::ProviderMetadata;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor,
};
use csaf_walker::visitors::skip::SkipExistingVisitor;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::fs;

/// Sync only what changed
#[derive(clap::Args, Debug)]
pub struct Report {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,

    /// Path of the data
    #[arg(short, long, default_value = "data")]
    data: PathBuf,

    #[command(flatten)]
    render: RenderOptions,
}

#[derive(clap::Args, Debug)]
pub struct RenderOptions {
    /// Path of the markdown output file
    #[arg(long, default_value = "report.md")]
    output_markdown: PathBuf,

    /// Path of the HTML output file
    #[arg(long, default_value = "report.html")]
    output_html: PathBuf,

    #[arg(long)]
    skip_markdown: bool,

    #[arg(long)]
    skip_html: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ReportResult<'d> {
    pub duplicates: &'d Duplicates,
    pub errors: &'d Vec<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Duplicates {
    pub duplicates: BTreeMap<String, usize>,
    pub known: HashSet<String>,
}

impl Report {
    pub async fn run(self) -> anyhow::Result<()> {
        let data = self.data;

        let options: ValidationOptions = self.validation.into();

        let duplicates = Arc::new(Mutex::new(Duplicates::default()));
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));

        {
            let duplicates = duplicates.clone();
            walk_visitor(self.client, self.discover, move |fetcher| async move {
                let visitor = {
                    let data = data.clone();

                    RetrievingVisitor::new(
                        fetcher.clone(),
                        ValidationVisitor::new(
                            fetcher.clone(),
                            move |advisory: Result<ValidatedAdvisory, ValidationError>| {
                                let data = data.clone();
                                async move {
                                    match advisory {
                                        Ok(advisory) => {
                                            log::info!("Downloading: {}", advisory.url);

                                            let file = PathBuf::from(advisory.url.path())
                                                .file_name()
                                                .map(|file| data.join(file))
                                                .ok_or_else(|| {
                                                    anyhow!("Unable to detect file name")
                                                })?;

                                            log::debug!("Writing {}", file.display());
                                            fs::write(file, &advisory.data)
                                                .await
                                                .context("Write advisory")?;
                                        }
                                        Err(err) => {
                                            log::warn!("Skipping erroneous advisory: {err}");
                                        }
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
                    visitor: SkipExistingVisitor {
                        visitor,
                        output: data,
                    },
                })
            })
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
        let mut md = String::with_capacity(256 * 1024);
        render::render_report(&mut md, &report)?;

        if !render.skip_markdown {
            std::fs::write(render.output_markdown, &md)?;
        }

        if !render.skip_html {
            let mut out = std::fs::File::create(&render.output_html)?;
            render::render_to_html(&md, &mut out)?;
        }

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
        metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(metadata).await
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
