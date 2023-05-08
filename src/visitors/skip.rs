use crate::discover::{DiscoveredAdvisory, DiscoveredVisitor};
use crate::model::metadata::ProviderMetadata;
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
        metadata: &ProviderMetadata,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(metadata)
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

        match fs::try_exists(self.output.join(name)).await? {
            true => {
                log::info!(
                    "Skipping existing file: {}",
                    name.to_str().unwrap_or_default()
                );
                Ok(())
            }
            false => self
                .visitor
                .visit_advisory(context, advisory)
                .await
                .map_err(Error::Visitor),
        }
    }
}
