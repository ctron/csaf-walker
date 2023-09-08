use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError};
use async_trait::async_trait;
use std::fmt::{Debug, Display};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, thiserror::Error)]
pub enum Error<VE: Display + Debug> {
    #[error("{0}")]
    Visitor(VE),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unable to get name from URL")]
    Name,
}

/// A visitor, skipping advisories for existing files.
pub struct SkipExistingVisitor<V: DiscoveredVisitor> {
    pub visitor: V,
    pub output: PathBuf,
}

#[async_trait(?Send)]
impl<V: DiscoveredVisitor> DiscoveredVisitor for SkipExistingVisitor<V> {
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &DiscoveredContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(context)
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        advisory: DiscoveredAdvisory,
    ) -> Result<(), Self::Error> {
        let name = PathBuf::from(advisory.url.path());
        let name = name.file_name().ok_or(Error::Name)?;

        let path = self.output.join(name);

        if fs::try_exists(&path).await? {
            if let Some(modified) = advisory.modified {
                let file_modified = fs::metadata(&path).await?.modified()?;

                log::debug!(
                    "Advisory modified: {}, file ({}) modified: {}",
                    humantime::Timestamp::from(modified),
                    name.to_string_lossy(),
                    humantime::Timestamp::from(file_modified)
                );

                if file_modified >= modified {
                    // the file was modified after the change date, skip it
                    return Ok(());
                }
            } else {
                log::debug!(
                    "Skipping file ({}), exists but was never modified",
                    name.to_string_lossy()
                );
                return Ok(());
            }
        }

        self.visitor
            .visit_advisory(context, advisory)
            .await
            .map_err(Error::Visitor)
    }
}

/// A visitor skipping failed [`ValidatedAdvisories`]
pub struct SkipFailedVisitor<V> {
    pub disabled: bool,
    pub visitor: V,
}

impl<V> SkipFailedVisitor<V> {
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,
            disabled: false,
        }
    }
}

#[async_trait(?Send)]
impl<V: ValidatedVisitor> ValidatedVisitor for SkipFailedVisitor<V> {
    type Error = V::Error;
    type Context = V::Context;

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor.visit_context(context).await
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        if let Err(err) = &result {
            log::warn!("Skipping failed advisory: {err}");
            return Ok(());
        }

        self.visitor.visit_advisory(context, result).await
    }
}
