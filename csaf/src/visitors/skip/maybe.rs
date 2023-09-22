use crate::retrieve::{RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor};
use crate::validation::{self, ValidatedVisitor, ValidationVisitor};
use async_trait::async_trait;
use std::fmt::{Debug, Display, Formatter};
use walker_common::validate::ValidationOptions;

/// A [`RetrievedVisitor`], which may skip validation.
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
