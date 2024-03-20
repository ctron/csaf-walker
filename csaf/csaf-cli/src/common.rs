use crate::cmd::DiscoverArguments;
use csaf_walker::{
    discover::DiscoveredVisitor,
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileOptions, FileSource, HttpOptions, HttpSource},
    validation::{ValidatedVisitor, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
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
    /// The URL to locate the provider metadata.
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

    if discover.source.starts_with("file:///") {
        if let Some(file_path) = discover.source.clone().strip_prefix("file:///") {
            // use a path
            Ok(FileSource::new(file_path, FileOptions::new().since(discover.since))?.into())
        } else {
            Err(anyhow::Error::msg(format!(
                "This is not a standard path, please check again carefully. : {}",
                discover.source.clone()
            )))
        }
    } else {
        if discover.source.clone().starts_with("http://")
            || discover.source.clone().starts_with("ftp://")
        {
            return Err(anyhow::Error::msg(format!(
                "This URL does not meet the definition of provider metadata sources according to CSAF standards. The URL {} not begin with 'https://'.",
                &discover.source
            )));
        }
        // use a URL
        log::info!("Fully provided discovery URL: {}", discover.source.clone());
        let fetcher = client.new_fetcher().await?;
        Ok(HttpSource::new(
            discover.source,
            fetcher,
            HttpOptions::new().since(discover.since),
        )
        .into())
    }
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
