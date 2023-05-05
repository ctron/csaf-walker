use crate::cmd::{DiscoverArguments, ValidationArguments};
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{
    ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor,
};
use csaf_walker::walker::Walker;
use std::future::Future;

pub async fn walk_standard<F, Fut>(
    discover: DiscoverArguments,
    validation: ValidationArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: Fn(Result<ValidatedAdvisory, ValidationError>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    walk_standard_ref(discover, validation, &f).await
}

async fn walk_standard_ref<F, Fut>(
    discover: DiscoverArguments,
    validation: ValidationArguments,
    f: &F,
) -> anyhow::Result<()>
where
    F: Fn(Result<ValidatedAdvisory, ValidationError>) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let client = reqwest::Client::new();

    let options: ValidationOptions = validation.into();

    Walker::new(discover.source, client.clone())
        .walk(RetrievingVisitor::new(
            client.clone(),
            ValidationVisitor::new(
                client,
                move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                    f(advisory).await
                },
            )
            .with_options(options),
        ))
        .await?;

    Ok(())
}
