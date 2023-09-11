use crate::cmd::{ClientArguments, DiscoverArguments, RunnerArguments, ValidationArguments};
use csaf_walker::{
    discover::DiscoveredVisitor,
    fetcher::{Fetcher, FetcherOptions},
    progress::Progress,
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileOptions, FileSource, HttpOptions, HttpSource},
    validation::{ValidatedVisitor, ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use reqwest::Url;
use std::future::Future;
use std::time::SystemTime;

pub async fn walk_standard<V>(
    progress: Progress,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: impl Into<DiscoverConfig>,
    validation: ValidationArguments,
    visitor: V,
) -> anyhow::Result<()>
where
    V: ValidatedVisitor,
    V::Error: Send + Sync + 'static,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(
        progress,
        client,
        discover,
        runner,
        move |source| async move {
            Ok(RetrievingVisitor::new(
                source.clone(),
                ValidationVisitor::new(visitor).with_options(options),
            ))
        },
    )
    .await
}

pub struct DiscoverConfig {
    /// The URL to locate the provider metadata.
    ///
    /// If `full` is `true`, this must be the full path to the `provider-metadata.json`, otherwise
    /// it `/.well-known/csaf/provider-metadata.json` will be appended.
    pub source: String,

    /// Mark the source as a full path to the metadata.
    pub full: bool,

    /// Only report documents which have changed since the provided date. If a document has no
    /// change information, or this field is [`None`], it wil always be reported.
    pub since: Option<SystemTime>,
}

impl DiscoverConfig {
    pub fn with_since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

impl From<DiscoverArguments> for DiscoverConfig {
    fn from(value: DiscoverArguments) -> Self {
        Self {
            since: None,
            source: value.source,
            full: value.full,
        }
    }
}

const WELL_KNOWN_METADATA: &str = ".well-known/csaf/provider-metadata.json";

pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    client: ClientArguments,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();

    match Url::parse(&discover.source) {
        Ok(mut url) => {
            if !discover.full && !url.path().ends_with("/provider-metadata.json") {
                url = url.join(WELL_KNOWN_METADATA)?;
                log::info!("Discovery URL: {url}");
            } else {
                log::info!("Fully provided discovery URL: {url}");
            }
            let fetcher = new_fetcher(client).await?;
            Ok(HttpSource {
                url,
                fetcher,
                options: HttpOptions {
                    since: discover.since,
                },
            }
            .into())
        }
        Err(_) => {
            // use as path
            Ok(FileSource::new(
                &discover.source,
                FileOptions {
                    since: discover.since,
                },
            )?
            .into())
        }
    }
}

pub async fn walk_visitor<F, Fut, V>(
    progress: Progress,
    client: ClientArguments,
    discover: impl Into<DiscoverConfig>,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let source = new_source(discover, client).await?;

    walk_source(progress, source, runner, f).await
}

pub async fn walk_source<F, Fut, V>(
    progress: Progress,
    source: DispatchSource,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let visitor = f(source.clone()).await?;
    let walker = Walker::new(source).with_progress(progress);

    match runner.workers {
        1 => {
            walker.walk(visitor).await?;
        }
        n => {
            walker.walk_parallel(n, visitor).await?;
        }
    }

    Ok(())
}

pub async fn new_fetcher(client: ClientArguments) -> Result<Fetcher, anyhow::Error> {
    Fetcher::new(FetcherOptions {
        timeout: client.timeout.into(),
        retries: client.retries,
    })
    .await
}
