use crate::retrieve::RetrievedDigest;
use anyhow::anyhow;
use bytes::Bytes;
use digest::Digest;
use futures_util::try_join;
use sha2::{Sha256, Sha512};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use url::Url;

pub async fn read_optional(path: impl AsRef<Path>) -> Result<Option<String>, anyhow::Error> {
    match tokio::fs::read_to_string(path).await {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn to_path(url: &Url) -> Result<PathBuf, anyhow::Error> {
    url.to_file_path()
        .map_err(|()| anyhow!("Failed to convert URL to path: {url}"))
}

/// Read the signature file and digests
///
/// The expected locations are:
/// * `{base}.asc`
/// * `{base}.sha256`
/// * `{base}.sha512`
pub async fn read_sig_and_digests(
    path: &Path,
    data: &Bytes,
) -> anyhow::Result<(
    Option<String>,
    Option<RetrievedDigest<Sha256>>,
    Option<RetrievedDigest<Sha512>>,
)> {
    let (signature, sha256, sha512) = try_join!(
        read_optional(format!("{}.asc", path.display())),
        read_optional(format!("{}.sha256", path.display())),
        read_optional(format!("{}.sha512", path.display())),
    )?;

    let sha256 = sha256
        // take the first "word" from the line
        .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
        .map(|expected| {
            let mut actual = Sha256::new();
            actual.update(data);
            RetrievedDigest::<Sha256> {
                expected,
                actual: actual.finalize(),
            }
        });

    let sha512 = sha512
        // take the first "word" from the line
        .and_then(|expected| expected.split(' ').next().map(ToString::to_string))
        .map(|expected| {
            let mut actual = Sha512::new();
            actual.update(data);
            RetrievedDigest::<Sha512> {
                expected,
                actual: actual.finalize(),
            }
        });

    Ok((signature, sha256, sha512))
}
