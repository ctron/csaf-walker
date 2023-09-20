use crate::retrieve::{RetrievalContext, RetrievalError, RetrievedSbom, RetrievedVisitor};
// use crate::validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError};
use crate::model::metadata::SourceMetadata;
use anyhow::Context;
use async_trait::async_trait;
use sequoia_openpgp::armor::Kind;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs;
use walker_common::utils::openpgp::PublicKey;

pub const DIR_METADATA: &str = "metadata";

/// Stores all data so that it can be used as a [`crate::source::Source`] later.
pub struct StoreVisitor {
    /// the output base
    pub base: PathBuf,

    /// whether to set the file modification timestamps
    pub no_timestamps: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0:#}")]
    Io(anyhow::Error),
    #[error("Failed to construct filename from URL: {0}")]
    Filename(String),
    #[error("Serialize key error: {0:#}")]
    SerializeKey(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreRetrievedError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

/*
#[derive(Debug, thiserror::Error)]
pub enum StoreValidatedError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}*/

#[async_trait(?Send)]
impl RetrievedVisitor for StoreVisitor {
    type Error = StoreRetrievedError;
    type Context = ();

    async fn visit_context(
        &self,
        context: &RetrievalContext,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.store_keys(context.keys).await?;
        Ok(())
    }

    async fn visit_sbom(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedSbom, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.store(&result?).await?;
        Ok(())
    }
}

/*
#[async_trait(?Send)]
impl ValidatedVisitor for StoreVisitor {
    type Error = StoreValidatedError;
    type Context = ();

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.store_keys(context.retrieval.keys).await?;
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        self.store(&result?.retrieved).await?;
        Ok(())
    }
}*/

impl StoreVisitor {
    async fn store_provider_metadata(&self, metadata: &SourceMetadata) -> Result<(), StoreError> {
        let file = self.base.join(DIR_METADATA).join("metadata.json");
        let mut out = std::fs::File::create(&file)
            .with_context(|| {
                format!(
                    "Unable to open provider metadata file for writing: {}",
                    file.display()
                )
            })
            .map_err(StoreError::Io)?;
        serde_json::to_writer_pretty(&mut out, metadata)
            .context("Failed serializing provider metadata")
            .map_err(StoreError::Io)?;
        Ok(())
    }

    async fn store_keys(&self, keys: &[PublicKey]) -> Result<(), StoreError> {
        let metadata = self.base.join(DIR_METADATA).join("keys");
        std::fs::create_dir(&metadata)
            // ignore if the directory already exists
            .or_else(|err| match err.kind() {
                ErrorKind::AlreadyExists => Ok(()),
                _ => Err(err),
            })
            .with_context(|| {
                format!(
                    "Failed to create metadata directory: {}",
                    metadata.display()
                )
            })
            .map_err(StoreError::Io)?;

        for cert in keys.iter().flat_map(|k| &k.certs) {
            log::info!("Storing key: {}", cert.fingerprint());
            self.store_cert(cert, &metadata).await?;
        }

        Ok(())
    }

    async fn store_cert(&self, cert: &Cert, path: &Path) -> Result<(), StoreError> {
        let name = path.join(format!("{}.txt", cert.fingerprint().to_hex()));

        let data = Self::serialize_key(cert).map_err(StoreError::SerializeKey)?;

        fs::write(&name, data)
            .await
            .with_context(|| format!("Failed to store key: {}", name.display()))
            .map_err(StoreError::Io)?;
        Ok(())
    }

    fn serialize_key(cert: &Cert) -> Result<Vec<u8>, anyhow::Error> {
        let mut writer = sequoia_openpgp::armor::Writer::new(Vec::new(), Kind::PublicKey)?;
        writer.write_all(&cert.to_vec()?)?;
        Ok(writer.finalize()?)
    }

    async fn store(&self, advisory: &RetrievedSbom) -> Result<(), StoreError> {
        log::info!(
            "Storing: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let file = PathBuf::from(advisory.url.path())
            .file_name()
            .map(|file| self.base.join(file))
            .ok_or_else(|| StoreError::Filename(advisory.url.to_string()))?;

        log::debug!("Writing {}", file.display());

        if let (Some(reported_modified), Some(stored_modified)) =
            (advisory.modified, advisory.metadata.last_modification)
        {
            if reported_modified != stored_modified {
                log::warn!(
                    "{}: Modification timestamp discrepancy - changes: {}, retrieved: {}",
                    file.display(),
                    humantime::Timestamp::from(reported_modified),
                    humantime::Timestamp::from(SystemTime::from(stored_modified)),
                );
            }
        }

        fs::write(&file, &advisory.data)
            .await
            .with_context(|| format!("Failed to write advisory: {}", file.display()))
            .map_err(StoreError::Io)?;

        if let Some(sha256) = &advisory.sha256 {
            let file = format!("{}.sha256", file.display());
            fs::write(&file, &sha256.expected)
                .await
                .with_context(|| format!("Failed to write checksum: {file}"))
                .map_err(StoreError::Io)?;
        }
        if let Some(sha512) = &advisory.sha512 {
            let file = format!("{}.sha512", file.display());
            fs::write(&file, &sha512.expected)
                .await
                .with_context(|| format!("Failed to write checksum: {file}"))
                .map_err(StoreError::Io)?;
        }
        if let Some(sig) = &advisory.signature {
            fs::write(format!("{}.asc", file.display()), &sig)
                .await
                .with_context(|| format!("Failed to write signature: {}", file.display()))
                .map_err(StoreError::Io)?;
        }

        if !self.no_timestamps {
            if let Some(time) = advisory.metadata.last_modification {
                // if we have the last modification time, set the file timestamp to it
                let time: SystemTime = time.into();
                filetime::set_file_mtime(&file, time.into())
                    .with_context(|| {
                        format!(
                            "Failed to set last modification timestamp: {}",
                            file.display()
                        )
                    })
                    .map_err(StoreError::Io)?;
            }
        }

        Ok(())
    }
}
