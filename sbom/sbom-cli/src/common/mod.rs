mod license;

pub use license::*;

use crate::cmd::DiscoverArguments;
use sbom_walker::{
    discover::{DiscoverConfig, DiscoveredVisitor},
    model::metadata,
    retrieve::RetrievingVisitor,
    source::DispatchSource,
    source::new_source,
    validation::{ValidatedVisitor, ValidationVisitor},
    walker::Walker,
};
use std::future::Future;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    validate::ValidationOptions,
};

pub async fn walk_standard<V, P>(
    progress: P,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: impl Into<DiscoverConfig>,
    validation: ValidationArguments,
    visitor: V,
) -> anyhow::Result<()>
where
    V: ValidatedVisitor<DispatchSource>,
    V::Error: Send + Sync + 'static,
    P: Progress,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(progress, client, discover, runner, async move |source| {
        Ok(RetrievingVisitor::new(
            source,
            ValidationVisitor::new(visitor).with_options(options),
        ))
    })
    .await
}

impl From<DiscoverArguments> for DiscoverConfig {
    fn from(value: DiscoverArguments) -> Self {
        Self {
            since: None,
            source: value.source,
            keys: value
                .keys
                .into_iter()
                .map(metadata::Key::from)
                .collect::<Vec<_>>(),
        }
    }
}

pub async fn walk_visitor<F, Fut, V, P>(
    progress: P,
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
    P: Progress,
{
    let source = new_source(discover, client).await?;

    walk_source(progress, source, runner, f).await
}

pub async fn walk_source<F, Fut, V, P>(
    progress: P,
    source: DispatchSource,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
    P: Progress,
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
