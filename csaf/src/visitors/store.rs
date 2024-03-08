use crate::{
    model::{metadata::ProviderMetadata, store::distribution_base},
    retrieve::{RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor},
    validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError},
};
use anyhow::Context;
use async_trait::async_trait;
use sequoia_openpgp::{armor::Kind, serialize::SerializeInto, Cert};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use tokio::fs;
use walker_common::{
    store::{store_document, Document, StoreError},
    utils::openpgp::PublicKey,
};

pub const DIR_METADATA: &str = "metadata";

/// Stores all data so that it can be used as a [`crate::source::Source`] later.
#[non_exhaustive]
pub struct StoreVisitor {
    /// the output base
    pub base: PathBuf,

    /// whether to set the file modification timestamps
    pub no_timestamps: bool,

    /// whether to store additional metadata (like the etag) using extended attributes
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub no_xattrs: bool,
}

impl StoreVisitor {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            no_timestamps: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            no_xattrs: false,
        }
    }

    pub fn no_timestamps(mut self, no_timestamps: bool) -> Self {
        self.no_timestamps = no_timestamps;
        self
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn no_xattrs(mut self, no_xattrs: bool) -> Self {
        self.no_xattrs = no_xattrs;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreRetrievedError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Retrieval(#[from] RetrievalError),
}

#[derive(Debug, thiserror::Error)]
pub enum StoreValidatedError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[async_trait(?Send)]
impl RetrievedVisitor for StoreVisitor {
    type Error = StoreRetrievedError;
    type Context = Rc<ProviderMetadata>;

    async fn visit_context(
        &self,
        context: &RetrievalContext,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.prepare_distributions(context.metadata).await?;
        self.store_keys(context.keys).await?;

        Ok(Rc::new(context.metadata.clone()))
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        self.store(&result?).await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl ValidatedVisitor for StoreVisitor {
    type Error = StoreValidatedError;
    type Context = ();

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.store_provider_metadata(context.metadata).await?;
        self.prepare_distributions(context.metadata).await?;
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
}

impl StoreVisitor {
    async fn prepare_distributions(&self, metadata: &ProviderMetadata) -> Result<(), StoreError> {
        for dist in &metadata.distributions {
            if let Some(directory_url) = &dist.directory_url {
                let base = distribution_base(&self.base, directory_url.as_str());
                log::debug!("Creating base distribution directory: {}", base.display());

                fs::create_dir_all(&base)
                    .await
                    .with_context(|| {
                        format!(
                            "Unable to create distribution directory: {}",
                            base.display()
                        )
                    })
                    .map_err(StoreError::Io)?;
            }
            if let Some(rolie) = &dist.rolie {
                for feed in &rolie.feeds {
                    let base = distribution_base(&self.base, feed.url.as_str());
                    fs::create_dir_all(&base)
                        .await
                        .with_context(|| {
                            format!(
                                "Unable to create distribution directory: {}",
                                base.display()
                            )
                        })
                        .map_err(StoreError::Io)?;
                }
            }
        }

        Ok(())
    }

    async fn store_provider_metadata(&self, metadata: &ProviderMetadata) -> Result<(), StoreError> {
        let metadir = self.base.join(DIR_METADATA);

        fs::create_dir(&metadir)
            .await
            .or_else(|err| match err.kind() {
                ErrorKind::AlreadyExists => Ok(()),
                _ => Err(err),
            })
            .with_context(|| format!("Failed to create metadata directory: {}", metadir.display()))
            .map_err(StoreError::Io)?;

        let file = metadir.join("provider-metadata.json");
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

    async fn store(&self, advisory: &RetrievedAdvisory) -> Result<(), StoreError> {
        log::info!(
            "Storing: {} (modified: {:?})",
            advisory.url,
            advisory.metadata.last_modification
        );

        let relative_url_result = advisory.context.url().make_relative(&advisory.url);
        let name = match &relative_url_result {
            Some(name) => name,
            None => return Err(StoreError::Filename(advisory.url.to_string())),
        };

        // create a distribution base
        let distribution_base = distribution_base(&self.base, advisory.context.url().as_str());

        // put the file there
        let file = distribution_base.join(name);

        store_document(
            &file,
            Document {
                data: &advisory.data,
                changed: advisory.modified,
                metadata: &advisory.metadata,
                sha256: &advisory.sha256,
                sha512: &advisory.sha512,
                signature: &advisory.signature,
                no_timestamps: self.no_timestamps,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                no_xattrs: self.no_xattrs,
            },
        )
        .await?;

        Ok(())
    }
}
