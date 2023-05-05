use csaf_walker::{
    retrieve::RetrievingVisitor,
    validation::{ValidatedAdvisory, ValidationError, ValidationOptions, ValidationVisitor},
    walker::Walker,
};
use reqwest::Url;
use std::convert::Infallible;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let client = reqwest::Client::new();

    let validation_date: SystemTime = humantime::parse_rfc3339_weak("2007-01-01 00:00:00")
        .expect("Valid timestamp")
        .into();

    Walker::new(
        Url::parse("https://access.redhat.com/security/data/csaf/v2/provider-metadata.json")
            .expect("Parse URL"),
        client.clone(),
    )
    .walk(RetrievingVisitor::new(
        client.clone(),
        ValidationVisitor::new(
            client,
            |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                match advisory {
                    Ok(adv) => {
                        log::info!("Advisory(OK)): {}", adv.retrieved.discovered.url);
                        log::info!("  SHA256: {:?}", adv.retrieved.sha256);
                        log::info!("  SHA512: {:?}", adv.retrieved.sha512);
                    }
                    Err(err) => {
                        log::info!("Advisory(ERR): {err}");
                    }
                }

                Ok::<_, Infallible>(())
            },
        )
        .with_options(ValidationOptions {
            validation_date: Some(validation_date),
            ..Default::default()
        }),
    ))
    .await?;

    Ok(())
}
