use crate::{cmd::DiscoverArguments, common::walk_standard};
use bzip2_rs::DecoderReader;
use sbom_walker::validation::{ValidatedSbom, ValidationError};
use sbom_walker::Sbom;
use std::borrow::Cow;
use std::io::Read;
use tokio::runtime::Handle;
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
            |advisory: Result<ValidatedSbom, ValidationError>| async move {
                match advisory {
                    Ok(adv) => {
                        println!("Advisory: {}", adv.url);
                        log::debug!("  Metadata: {:?}", adv.sha256);
                        log::debug!("    SHA256: {:?}", adv.sha256);
                        log::debug!("    SHA512: {:?}", adv.sha512);

                        let data = if adv.url.path().ends_with(".bz2") {
                            let mut decoder = DecoderReader::new(adv.data.as_ref());
                            let mut data = vec![];
                            decoder.read_to_end(&mut data)?;
                            Cow::<[u8]>::Owned(data)
                        } else {
                            Cow::Borrowed(adv.data.as_ref())
                        };

                        match Sbom::try_parse_any(&data) {
                            Ok(sbom) => {
                                Handle::current()
                                    .spawn_blocking(move || process_sbom(sbom))
                                    .await?;
                            }

                            Err(err) => {
                                eprintln!("  Format error: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("SBOM(ERR): {err}");
                    }
                }

                Ok::<_, anyhow::Error>(())
            },
        )
        .await?;

        Ok(())
    }
}

fn process_sbom(sbom: Sbom) {
    match sbom {
        Sbom::Spdx(sbom) => {
            println!(
                "  SPDX: {}",
                sbom.document_creation_information.document_name
            );
        }
        Sbom::CycloneDx(_sbom) => {
            println!("  CycloneDX");
        }
    }
}
