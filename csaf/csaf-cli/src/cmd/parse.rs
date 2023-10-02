use std::path::PathBuf;

use csaf::Csaf;
use walker_common::progress::Progress;

/// Parse advisories
#[derive(clap::Args, Debug)]
pub struct Parse {
    file: PathBuf,
}

impl Parse {
    pub async fn run(self, progress: Progress) -> anyhow::Result<()> {
        progress.start(1);
        let data = std::fs::read(&self.file)?;
        match serde_json::from_slice::<Csaf>(&data) {
            Ok(csaf) => {
                println!(
                    "  {} ({}): {}",
                    csaf.document.tracking.id, csaf.document.tracking.initial_release_date, csaf.document.title
                );
            }
            Err(err) => {
                eprintln!("  Format error: {err}");
            }
        }

        Ok(())
    }
}
