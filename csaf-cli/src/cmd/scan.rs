use crate::cmd::{ClientArguments, DiscoverArguments, ValidationArguments};
use crate::common::walk_standard;
use csaf::Csaf;

/// Scan advisories
#[derive(clap::Args, Debug)]
pub struct Scan {
    #[command(flatten)]
    client: ClientArguments,

    #[command(flatten)]
    discover: DiscoverArguments,

    #[command(flatten)]
    validation: ValidationArguments,
}

impl Scan {
    pub async fn run(self) -> anyhow::Result<()> {
        walk_standard(
            self.client,
            self.discover,
            self.validation,
            |advisory| async {
                match advisory {
                    Ok(adv) => {
                        log::info!("Advisory: {}", adv.url);
                        log::debug!("  Metadata: {:?}", adv.sha256);
                        log::debug!("    SHA256: {:?}", adv.sha256);
                        log::debug!("    SHA512: {:?}", adv.sha512);
                        match serde_json::from_slice::<Csaf>(&adv.data) {
                            Ok(csaf) => {
                                log::info!(
                                    "  {} ({}): {}",
                                    csaf.document.tracking.id,
                                    csaf.document.tracking.initial_release_date,
                                    csaf.document.title
                                );
                            }
                            Err(err) => {
                                log::warn!("  Format error: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        log::warn!("Advisory(ERR): {err}");
                    }
                }

                Ok(())
            },
        )
        .await?;

        Ok(())
    }
}
