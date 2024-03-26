use crate::cmd::DiscoverArguments;
use csaf_walker::{
    discover::DiscoveredVisitor,
    retrieve::RetrievingVisitor,
    source::DispatchSource,
    source::{input_string_dispatch, DiscoverConfig},
    validation::{ValidatedVisitor, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use std::future::Future;
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

    input_string_dispatch(discover, client.new_fetcher().await?).await
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
