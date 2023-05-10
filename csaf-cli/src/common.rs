use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
use csaf_walker::discover::DiscoveredVisitor;
use csaf_walker::source::HttpSource;
use csaf_walker::validation::ValidatedVisitor;
use csaf_walker::{
    fetcher::{Fetcher, FetcherOptions},
    retrieve::RetrievingVisitor,
    validation::{ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use std::future::Future;

pub async fn walk_standard<V>(
    client: ClientArguments,
    discover: DiscoverArguments,
    validation: ValidationArguments,
    visitor: V,
) -> anyhow::Result<()>
where
    V: ValidatedVisitor,
    V::Error: Send + Sync + 'static,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(client, discover, move |source| async move {
        Ok(RetrievingVisitor::new(
            source.clone(),
            ValidationVisitor::new(visitor).with_options(options),
        ))
    })
    .await
}

pub async fn walk_visitor<F, Fut, V>(
    client: ClientArguments,
    discover: DiscoverArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(HttpSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let fetcher = new_fetcher(client).await?;

    let source = HttpSource {
        url: discover.source,
        fetcher,
    };

    let visitor = f(source.clone()).await?;

    let walker = Walker::new(source);

    match discover.workers {
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
