use crate::cmd::{ClientArguments, DiscoverArguments, RunnerArguments, ValidationArguments};
use csaf_walker::discover::DiscoveredVisitor;
use csaf_walker::progress::Progress;
use csaf_walker::source::{DispatchSource, FileSource, HttpSource};
use csaf_walker::validation::ValidatedVisitor;
use csaf_walker::{
    fetcher::{Fetcher, FetcherOptions},
    retrieve::RetrievingVisitor,
    validation::{ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use reqwest::Url;
use std::future::Future;

pub async fn walk_standard<V>(
    progress: Progress,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: DiscoverArguments,
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

pub async fn new_source(
    discover: DiscoverArguments,
    client: ClientArguments,
) -> anyhow::Result<DispatchSource> {
    match Url::parse(&discover.source) {
        Ok(url) => {
            let fetcher = new_fetcher(client).await?;
            Ok(HttpSource { url, fetcher }.into())
        }
        Err(_) => {
            // use as path
            Ok(FileSource::new(&discover.source)?.into())
        }
    }
}

pub async fn walk_visitor<F, Fut, V>(
    progress: Progress,
    client: ClientArguments,
    discover: DiscoverArguments,
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
