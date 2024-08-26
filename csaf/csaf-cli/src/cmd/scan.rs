use crate::{
    cmd::{DiscoverArguments, FilterArguments},
    common::walk_standard,
};
use csaf::Csaf;
use csaf_walker::validation::{ValidatedAdvisory, ValidationError};
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
};

/// Scan advisories
#[derive(clap::Args, Debug)]
pub struct Scan {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    runner: RunnerArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    filter: FilterArguments,

    #[command(flatten)]
    validation: ValidationArguments,
}

impl Scan {
    pub async fn run<P: Progress>(self, progress: P) -> anyhow::Result<()> {
        walk_standard(
            progress,
            self.client,
            self.runner,
            self.discover,
            self.filter,
            self.validation,
            |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                match advisory {
                    Ok(adv) => {
                        println!("Advisory: {}", adv.url);
                        log::debug!("  Metadata: {:?}", adv.sha256);
                        log::debug!("    SHA256: {:?}", adv.sha256);
                        log::debug!("    SHA512: {:?}", adv.sha512);
                        match serde_json::from_slice::<Csaf>(&adv.data) {
                            Ok(csaf) => {
                                println!(
                                    "  {} ({}): {}",
                                    csaf.document.tracking.id,
                                    csaf.document.tracking.initial_release_date,
                                    csaf.document.title
                                );
                            }
                            Err(err) => {
                                eprintln!("  Format error: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("Advisory(ERR): {err}");
                    }
                }

                Ok::<_, anyhow::Error>(())
            },
        )
        .await?;

        Ok(())
    }
}
