use crate::{
    discover::DiscoveredAdvisory,
    model::{
        metadata::{self, Distribution, ProviderMetadata},
        store::distribution_base,
    },
    retrieve::{RetrievalMetadata, RetrievedAdvisory},
    source::Source,
    visitors::store::{ATTR_ETAG, DIR_METADATA},
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use url::Url;
use walkdir::WalkDir;
use walker_common::{
    source::file::{read_sig_and_digests, to_path},
    utils::{self, openpgp::PublicKey},
    validate::source::{Key, KeySource, KeySourceError},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileOptions {
    pub since: Option<SystemTime>,
}

/// A file based source, possibly created by the [`crate::visitors::store::StoreVisitor`].
#[derive(Clone)]
pub struct FileSource {
    /// the path to the storage base, an absolute path
    base: PathBuf,
    options: FileOptions,
}

impl FileSource {
    pub fn new(
        base: impl AsRef<Path>,
        options: impl Into<Option<FileOptions>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base: fs::canonicalize(base)?,
            options: options.into().unwrap_or_default(),
        })
    }

    async fn scan_keys(&self) -> Result<Vec<metadata::Key>, anyhow::Error> {
        let dir = self.base.join(DIR_METADATA).join("keys");

        let mut result = Vec::new();

        let mut entries = match tokio::fs::read_dir(&dir).await {
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(result);
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Failed scanning for keys: {}", dir.display()));
            }
            Ok(entries) => entries,
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            match path
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.rsplit_once('.'))
            {
                Some((name, "txt")) => result.push(metadata::Key {
                    fingerprint: Some(name.to_string()),
                    url: Url::from_file_path(&path).map_err(|()| {
                        anyhow!("Failed to build file URL for: {}", path.display())
                    })?,
                }),
                Some((_, _)) | None => {}
            }
        }

        Ok(result)
    }

    /// walk a distribution directory
    fn walk_distribution(
        &self,
        distribution: &Distribution,
    ) -> Result<mpsc::Receiver<walkdir::Result<walkdir::DirEntry>>, anyhow::Error> {
        let (tx, rx) = mpsc::channel(8);

        let path = distribution.directory_url.to_file_path().map_err(|()| {
            anyhow!(
                "Failed to convert into path: {}",
                distribution.directory_url
            )
        })?;

        tokio::task::spawn_blocking(move || {
            for entry in WalkDir::new(path).into_iter().filter_entry(|entry| {
                // if it's a file but doesn't end with .json -> skip it
                !entry.file_type().is_file()
                    || entry.file_name().to_string_lossy().ends_with(".json")
            }) {
                if let Err(err) = tx.blocking_send(entry) {
                    // channel closed, abort
                    log::debug!("Send error: {err}");
                    return;
                }
            }
            log::debug!("Finished walking files");
        });

        Ok(rx)
    }
}

#[async_trait(?Send)]
impl Source for FileSource {
    type Error = anyhow::Error;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        let metadata = self.base.join(DIR_METADATA).join("provider-metadata.json");
        let file = fs::File::open(&metadata)
            .with_context(|| format!("Failed to open file: {}", metadata.display()))?;

        let mut metadata: ProviderMetadata =
            serde_json::from_reader(&file).context("Failed to read stored provider metadata")?;

        metadata.public_openpgp_keys = self.scan_keys().await?;

        for dist in &mut metadata.distributions {
            let distribution_base = distribution_base(&self.base, &dist);
            let directory_url = Url::from_directory_path(&distribution_base).map_err(|()| {
                anyhow!(
                    "Failed to convert directory into URL: {}",
                    self.base.display(),
                )
            })?;

            dist.directory_url = directory_url;
        }

        // return result

        Ok(metadata)
    }

    async fn load_index(
        &self,
        distribution: Distribution,
    ) -> Result<Vec<DiscoveredAdvisory>, Self::Error> {
        log::info!("Loading index - since: {:?}", self.options.since);

        let distribution = Arc::new(distribution);

        let mut entries = self.walk_distribution(&distribution)?;
        let mut result = vec![];

        while let Some(entry) = entries.recv().await {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|s| s.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !name.ends_with(".json") {
                continue;
            }

            if let Some(since) = self.options.since {
                let modified = path.metadata()?.modified()?;
                if modified < since {
                    log::debug!("Skipping file due to modification constraint: {modified:?}");
                    continue;
                }
            }

            let url = Url::from_file_path(&path)
                .map_err(|()| anyhow!("Failed to convert to URL: {}", path.display()))?;

            let modified = path.metadata()?.modified()?;

            result.push(DiscoveredAdvisory {
                url,
                modified,
                distribution: distribution.clone(),
            })
        }

        Ok(result)
    }

    async fn load_advisory(
        &self,
        discovered: DiscoveredAdvisory,
    ) -> Result<RetrievedAdvisory, Self::Error> {
        let path = discovered
            .url
            .to_file_path()
            .map_err(|()| anyhow!("Unable to convert URL into path: {}", discovered.url))?;

        let data = Bytes::from(tokio::fs::read(&path).await?);

        let (signature, sha256, sha512) = read_sig_and_digests(&path, &data).await?;

        let last_modification = path
            .metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .map(OffsetDateTime::from);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let etag = xattr::get(&path, ATTR_ETAG)
            .transpose()
            .and_then(|r| r.ok())
            .and_then(|s| String::from_utf8(s).ok());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let etag = None;

        Ok(RetrievedAdvisory {
            discovered,
            data,
            signature,
            sha256,
            sha512,
            metadata: RetrievalMetadata {
                last_modification,
                etag,
            },
        })
    }
}

#[async_trait(?Send)]
impl KeySource for FileSource {
    type Error = anyhow::Error;

    async fn load_public_key<'a>(
        &self,
        key: Key<'a>,
    ) -> Result<PublicKey, KeySourceError<Self::Error>> {
        let bytes = tokio::fs::read(to_path(key.url).map_err(KeySourceError::Source)?)
            .await
            .map_err(|err| KeySourceError::Source(err.into()))?;
        utils::openpgp::validate_keys(bytes.into(), key.fingerprint)
            .map_err(KeySourceError::OpenPgp)
    }
}
