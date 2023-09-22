use crate::discover::{DiscoveredAdvisory, DiscoveredContext, DiscoveredVisitor};
use crate::retrieve::{RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor};
use crate::validation;
use crate::validation::{
    ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError, ValidationVisitor,
};
use async_trait::async_trait;
use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::fs;
use walker_common::validate::ValidationOptions;

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
    /// The time "since" when we consider changes "new"
    ///
    /// Overrides the "file modified" timestamp which is used by default.
    pub since: Option<SystemTime>,
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
                // if we have a "since", we use it as the file modification timestamp
                let file_modified = match self.since {
                    Some(since) => since,
                    None => fs::metadata(&path).await?.modified()?,
                };

                log::debug!(
                    "Advisory modified: {}, file ({}) modified: {} ({:?})",
                    humantime::Timestamp::from(modified),
                    name.to_string_lossy(),
                    humantime::Timestamp::from(file_modified),
                    self.since.map(humantime::Timestamp::from)
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

pub enum MaySkipValidationVisitor<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    Enabled(ValidationVisitor<V>),
    Disabled(V),
}

impl<V> MaySkipValidationVisitor<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    pub fn new(disabled: bool, visitor: V, options: Option<ValidationOptions>) -> Self {
        match disabled {
            true => Self::Disabled(visitor),
            false => {
                let visitor = ValidationVisitor::new(visitor);
                let visitor = match options {
                    Some(options) => visitor.with_options(options),
                    None => visitor,
                };
                Self::Enabled(visitor)
            }
        }
    }
}

pub enum MaySkipValidationError<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    Retrieved(<V as RetrievedVisitor>::Error),
    Validated(validation::Error<<V as ValidatedVisitor>::Error>),
}

pub enum MaySkipValidationContext<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    Retrieved(<V as RetrievedVisitor>::Context),
    Validated(validation::InnerValidationContext<<V as ValidatedVisitor>::Context>),
}

impl<V> MaySkipValidationContext<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    fn as_retrieved(&self) -> Option<&<V as RetrievedVisitor>::Context> {
        match self {
            Self::Retrieved(context) => Some(context),
            _ => None,
        }
    }

    fn as_validated(
        &self,
    ) -> Option<&validation::InnerValidationContext<<V as ValidatedVisitor>::Context>> {
        match self {
            Self::Validated(context) => Some(context),
            _ => None,
        }
    }
}

impl<V> Debug for MaySkipValidationError<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retrieved(err) => f.debug_tuple("Retrieved").field(err).finish(),
            Self::Validated(err) => f.debug_tuple("Validated").field(err).finish(),
        }
    }
}
impl<V> Display for MaySkipValidationError<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retrieved(err) => Display::fmt(err, f),
            Self::Validated(err) => Display::fmt(err, f),
        }
    }
}

#[async_trait(?Send)]
impl<V> RetrievedVisitor for MaySkipValidationVisitor<V>
where
    V: RetrievedVisitor + ValidatedVisitor,
{
    type Error = MaySkipValidationError<V>;
    type Context = MaySkipValidationContext<V>;

    async fn visit_context(
        &self,
        context: &RetrievalContext,
    ) -> Result<Self::Context, Self::Error> {
        match self {
            Self::Enabled(visitor) => visitor
                .visit_context(context)
                .await
                .map(Self::Context::Validated)
                .map_err(Self::Error::Validated),
            Self::Disabled(visitor) => RetrievedVisitor::visit_context(visitor, context)
                .await
                .map(Self::Context::Retrieved)
                .map_err(Self::Error::Retrieved),
        }
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Enabled(visitor) => visitor
                .visit_advisory(context.as_validated().unwrap(), result)
                .await
                .map_err(Self::Error::Validated),
            Self::Disabled(visitor) => {
                RetrievedVisitor::visit_advisory(visitor, context.as_retrieved().unwrap(), result)
                    .await
                    .map_err(Self::Error::Retrieved)
            }
        }
    }
}

pub struct SkipFailedVisitor<V> {
    pub visitor: V,
}

impl<V> SkipFailedVisitor<V> {
    pub fn new(visitor: V) -> Self {
        Self { visitor }
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
