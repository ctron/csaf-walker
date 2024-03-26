use crate::cmd::DiscoverArguments;
use csaf_walker::{
    discover::DiscoveredVisitor,
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileOptions, FileSource, HttpOptions, HttpSource},
    validation::{ValidatedVisitor, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use reqwest::Url;
use std::future::Future;
use std::time::SystemTime;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    validate::ValidationOptions,
};

pub async fn walk_standard<V>(
    progress: Progress,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
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
        filter,
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
    /// The URL to locate the provider metadata or as a base domain, in order to facilitate automatic querying of provider metadata URL..
    pub source: String,

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
        }
    }
}

pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    client: ClientArguments,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();

    let url_parse_result = Url::parse(discover.source.as_str());
    if let Ok(url) = url_parse_result.clone() {
        log::info!("The URl {:?}", url.clone());
        if url.scheme() == "https" {
            // handle direct URL case
            log::info!("Fully provided discovery URL: {}", discover.source.clone());
            let fetcher = client.new_fetcher().await?;
            return Ok(HttpSource::new(
                url.to_string(),
                fetcher,
                HttpOptions::new().since(discover.since),
            )
            .into());
        }
        // When the scheme of the input URL is "http" or "ftp", it should be interpreted as a host string.
        if (url.scheme() == "http") || (url.scheme() == "ftp") {
            if let Some(host_str) = url.host_str() {
                let fetcher = client.new_fetcher().await?;
                return Ok(HttpSource::new(
                    host_str.to_string(),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into());
            }
        }
    }

    if let Err(e) = url_parse_result.clone() {
        match e {
            url::ParseError::RelativeUrlWithoutBase => {
                log::info!("The URl does not have scheme, will treat it as base domain");
                let fetcher = client.new_fetcher().await?;
                return Ok(HttpSource::new(
                    discover.source.clone(),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into());
            }
            _ => {
                return Err(anyhow::Error::msg(format!(
                    "This is not a standard URL {}, please check again carefully. : {:?}",
                    discover.source.clone(),
                    e
                )))
            }
        }
    }

    // When the scheme of the input URL is "file", it should be interpreted as a file path.
    if discover.source.clone().starts_with("file://") {
        if let Some(path) = discover.source.clone().strip_prefix("file://") {
            return Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into());
        } else {
            return Err(anyhow::Error::msg(format!(
                "This is not a standard path or the path does not exist. Please double-check carefully. : {}",
                discover.source.clone()
            )));
        }
    }
    if discover.source.clone().starts_with("file:") {
        if let Some(path) = discover.source.clone().strip_prefix("file:") {
            return Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into());
        } else {
            return Err(anyhow::Error::msg(format!(
                "This is not a standard path or the path does not exist. Please double-check carefully. : {}",
                discover.source.clone()
            )));
        }
    }
    Err(anyhow::Error::msg(format!(
        "This is not a standard URL or the path does not exist , please check again carefully. : {}",
        discover.source.clone()
    )))
}

/// Create a [`FilteringVisitor`] from a [`FilterConfig`].
pub fn filter<V>(filter: impl Into<FilterConfig>, visitor: V) -> FilteringVisitor<V>
where
    V: DiscoveredVisitor,
{
    FilteringVisitor {
        visitor,
        config: filter.into(),
    }
}

pub async fn walk_visitor<F, Fut, V>(
    progress: Progress,
    client: ClientArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
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

    walk_source(progress, source, filter, runner, f).await
}

pub async fn walk_source<F, Fut, V>(
    progress: Progress,
    source: DispatchSource,
    filter_config: impl Into<FilterConfig>,
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
            walker.walk(filter(filter_config, visitor)).await?;
        }
        n => {
            walker
                .walk_parallel(n, filter(filter_config, visitor))
                .await?;
        }
    }

    Ok(())
}
