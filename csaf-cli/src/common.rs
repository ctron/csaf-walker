use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
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
    let fetcher = Fetcher::new(FetcherOptions {
        timeout: client.timeout.into(),
        retries: client.retries,
    })
    .await?;

    let options: ValidationOptions = validation.into();

    Walker::new(discover.source, fetcher.clone())
        .walk(RetrievingVisitor::new(
            fetcher.clone(),
            ValidationVisitor::new(
                fetcher,
                move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                    f(advisory).await
                },
            )
            .with_options(options),
        ))
        .await?;

    Ok(())
}
