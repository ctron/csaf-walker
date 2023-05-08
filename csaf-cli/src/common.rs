use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
use csaf_walker::discover::DiscoveredVisitor;
use csaf_walker::{
    fetcher::{Fetcher, FetcherOptions},
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use std::future::Future;

pub async fn walk_standard<F, Fut>(
    client: ClientArguments,
    discover: DiscoverArguments,
    validation: ValidationArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: Fn(Result<ValidatedAdvisory, ValidationError>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    walk_standard_ref(client, discover, validation, &f).await
}

async fn walk_standard_ref<F, Fut>(
    client: ClientArguments,
    discover: DiscoverArguments,
    validation: ValidationArguments,
    f: &F,
) -> anyhow::Result<()>
where
    F: Fn(Result<ValidatedAdvisory, ValidationError>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(client, discover, move |fetcher| async move {
        Ok(RetrievingVisitor::new(
            fetcher.clone(),
            ValidationVisitor::new(
                fetcher.clone(),
                move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                    f(advisory).await
                },
            )
            .with_options(options),
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
    F: FnOnce(Fetcher) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let fetcher = new_fetcher(client).await?;
    let visitor = f(fetcher.clone()).await?;

    let walker = Walker::new(discover.source, fetcher);

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
