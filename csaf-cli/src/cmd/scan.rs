use crate::cmd::{ClientArguments, DiscoverArguments, RunnerArguments, ValidationArguments};
use crate::common::walk_standard;
use csaf::Csaf;
use csaf_walker::progress::Progress;
use csaf_walker::validation::{ValidatedAdvisory, ValidationError};

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
    validation: ValidationArguments,
}

impl Scan {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        walk_standard(
            progress,
            self.client,
            self.runner,
            self.discover,
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
