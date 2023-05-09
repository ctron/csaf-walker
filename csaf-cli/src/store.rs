use anyhow::{anyhow, Context};
use csaf_walker::validation::ValidatedAdvisory;
use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::fs;
use xattr;

#[cfg(not(target_os = "linux"))]
const ATTR_ETAG: &str = "etag";
#[cfg(target_os = "linux")]
const ATTR_ETAG: &str = "user.etag";

pub async fn store_advisory(
    base: &Path,
    advisory: ValidatedAdvisory,
    skip_attr: bool,
) -> anyhow::Result<()> {
    log::info!("Storing: {}", advisory.url);

    let file = PathBuf::from(advisory.url.path())
        .file_name()
        .map(|file| base.join(file))
        .ok_or_else(|| anyhow!("Unable to detect file name"))?;

    log::debug!("Writing {}", file.display());
    fs::write(&file, &advisory.data)
        .await
        .context("Write advisory")?;

    if let Some(sha256) = &advisory.sha256 {
        fs::write(format!("{}.sha256", file.display()), &sha256.expected).await?;
    }
    if let Some(sha512) = &advisory.sha512 {
        fs::write(format!("{}.sha512", file.display()), &sha512.expected).await?;
    }
    if let Some(sig) = &advisory.signature {
        fs::write(format!("{}.sha512", file.display()), &sig).await?;
    }

    if let Some(time) = advisory.metadata.last_modification {
        // if we have the last modification time, set the file timestamp to it
        let time: SystemTime = time.into();
        filetime::set_file_mtime(&file, time.into()).context("Setting file modification time")?;
    }

    if !skip_attr {
        if let Some(etag) = &advisory.metadata.etag {
            xattr::set(&file, ATTR_ETAG, etag.as_bytes()).context("Storing etag")?;
        }
    }

    Ok(())
}
