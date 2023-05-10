use crate::discover::DiscoveredAdvisory;
use crate::model::metadata::{Distribution, Key, ProviderMetadata};
use crate::retrieve::{RetrievalMetadata, RetrievedAdvisory, RetrievedDigest};
use crate::source::{KeySource, KeySourceError, Source};
use crate::utils;
use crate::utils::openpgp::PublicKey;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use bytes::Bytes;
use digest::Digest;
use futures::try_join;
use sha2::{Sha256, Sha512};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use url::Url;

/// A file based source, possibly created by the [`crate::visitors::store::StoreVisitor`].
#[derive(Clone)]
pub struct FileSource {
    /// the path to the storage base, an absolute path
    base: PathBuf,
}

impl FileSource {
    pub fn new(base: impl AsRef<Path>) -> anyhow::Result<Self> {
        Ok(Self {
            base: fs::canonicalize(base)?,
        })
    }

    async fn scan_keys(&self) -> Result<Vec<Key>, anyhow::Error> {
        let dir = self.base.join("metadata").join("keys");

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
                Some((name, "txt")) => result.push(Key {
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
}

#[async_trait(?Send)]
impl Source for FileSource {
    type Error = anyhow::Error;

    async fn load_metadata(&self) -> Result<ProviderMetadata, Self::Error> {
        let metadata = self.base.join("provider-metadata.json");
        let file = fs::File::open(&metadata)
            .with_context(|| format!("Failed to open file: {}", metadata.display()))?;

        let mut metadata: ProviderMetadata =
            serde_json::from_reader(&file).context("Failed to read stored provider metadata")?;

        let base = Url::from_directory_path(&self.base).map_err(|()| {
            anyhow!(
                "Failed to convert directory into URL: {}",
                self.base.display(),
            )
        })?;

        metadata.public_openpgp_keys = self.scan_keys().await?;
        metadata.distributions = vec![Distribution {
            directory_url: base,
        }];

        Ok(metadata)
    }

    async fn load_index(&self, distribution: &Distribution) -> Result<Vec<Url>, Self::Error> {
        let path = &distribution.directory_url.to_file_path().map_err(|()| {
            anyhow!(
                "Failed to convert into path: {}",
                distribution.directory_url
            )
        })?;

        let mut entries = tokio::fs::read_dir(path).await?;
        let mut result = vec![];

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".json") {
                    result.push(
                        Url::from_file_path(&path).map_err(|()| {
                            anyhow!("Failed to convert to URL: {}", path.display())
                        })?,
                    )
                }
            }
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
                actual.update(&data);
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
                actual.update(&data);
                RetrievedDigest::<Sha512> {
                    expected,
                    actual: actual.finalize(),
                }
            });

        let last_modification = path
            .metadata()
            .ok()
            .and_then(|md| md.modified().ok())
            .map(|mtime| OffsetDateTime::from(mtime));

        Ok(RetrievedAdvisory {
            discovered,
            data,
            signature,
            sha256,
            sha512,
            metadata: RetrievalMetadata {
                last_modification,
                etag: None,
            },
        })
    }
}

async fn read_optional(path: impl AsRef<Path>) -> Result<Option<String>, anyhow::Error> {
    match tokio::fs::read_to_string(path).await {
        Ok(data) => Ok(Some(data)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn to_path(url: &Url) -> Result<PathBuf, anyhow::Error> {
    url.to_file_path()
        .map_err(|()| anyhow!("Failed to convert URL to path: {url}"))
}

#[async_trait(?Send)]
impl KeySource for FileSource {
    type Error = anyhow::Error;

    async fn load_public_key(&self, key: &Key) -> Result<PublicKey, KeySourceError<Self::Error>> {
        let bytes = tokio::fs::read(to_path(&key.url).map_err(KeySourceError::Source)?)
            .await
            .map_err(|err| KeySourceError::Source(err.into()))?;
        utils::openpgp::validate_keys(bytes.into(), &key.fingerprint)
            .map_err(KeySourceError::OpenPgp)
    }
}
