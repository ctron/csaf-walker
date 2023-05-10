//! Validation

mod openpgp;

use crate::retrieve::{
    RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedDigest, RetrievedVisitor,
};
use crate::utils::openpgp::PublicKey;
use async_trait::async_trait;
use digest::Digest;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::time::SystemTime;
use url::Url;

#[derive(Clone, Debug)]
pub struct ValidatedAdvisory {
    /// The discovered advisory
    pub retrieved: RetrievedAdvisory,
}

impl Deref for ValidatedAdvisory {
    type Target = RetrievedAdvisory;

    fn deref(&self) -> &Self::Target {
        &self.retrieved
    }
}

impl DerefMut for ValidatedAdvisory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.retrieved
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    Retrieval(RetrievalError),
    DigestMismatch {
        expected: String,
        actual: String,
        retrieved: RetrievedAdvisory,
    },
    Signature {
        error: anyhow::Error,
        retrieved: RetrievedAdvisory,
    },
}

impl ValidationError {
    pub fn url(&self) -> &Url {
        match self {
            Self::Retrieval(err) => err.url(),
            Self::DigestMismatch { retrieved, .. } => &retrieved.url,
            Self::Signature { retrieved, .. } => &retrieved.url,
        }
    }
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retrieval(err) => write!(f, "Retrieval error: {err}"),
            Self::DigestMismatch {
                expected,
                actual,
                retrieved,
            } => write!(
                f,
                "Digest mismatch - expected: {expected}, actual: {actual} ({})",
                retrieved.url
            ),
            Self::Signature { error, retrieved } => {
                write!(f, "Invalid signature: {error} ({})", retrieved.url)
            }
        }
    }
}

pub struct ValidationContext<'c> {
    pub retrieval: &'c RetrievalContext<'c>,
}

impl<'c> Deref for ValidationContext<'c> {
    type Target = RetrievalContext<'c>;

    fn deref(&self) -> &Self::Target {
        &self.retrieval
    }
}

#[async_trait(?Send)]
pub trait ValidatedVisitor {
    type Error: Display + Debug;
    type Context;

    async fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error>;

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
impl<F, E, Fut> ValidatedVisitor for F
where
    F: Fn(Result<ValidatedAdvisory, ValidationError>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Display + Debug,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        self(result).await
    }
}

#[derive(Clone, Debug, Default)]
pub struct ValidationOptions {
    /// time for policy checks
    pub validation_date: Option<SystemTime>,
}

pub struct ValidationVisitor<V>
where
    V: ValidatedVisitor,
{
    visitor: V,
    options: ValidationOptions,
}

enum ValidationProcessError {
    /// Failed, but passing on to visitor
    Proceed(ValidationError),
    /// Failed, aborting processing
    #[allow(unused)]
    Abort(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: Display + Debug,
{
    #[error("{0}")]
    Visitor(VE),
    #[error("Severe validation error: {0}")]
    Validation(anyhow::Error),
}

impl<V> ValidationVisitor<V>
where
    V: ValidatedVisitor,
{
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,

            options: Default::default(),
        }
    }

    pub fn with_options(mut self, options: impl Into<ValidationOptions>) -> Self {
        self.options = options.into();
        self
    }

    /// Perform the actual validation.
    ///
    /// Returning either a processing error, or a result which will will be forwarded to the visitor.
    async fn validate(
        &self,
        context: &InnerValidationContext<V::Context>,
        retrieved: RetrievedAdvisory,
    ) -> Result<ValidatedAdvisory, ValidationProcessError> {
        if let Err((expected, actual)) = Self::validate_digest(&retrieved.sha256) {
            return Err(ValidationProcessError::Proceed(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            ));
        }
        if let Err((expected, actual)) = Self::validate_digest(&retrieved.sha512) {
            return Err(ValidationProcessError::Proceed(
                ValidationError::DigestMismatch {
                    expected,
                    actual,
                    retrieved,
                },
            ));
        }

        if let Some(signature) = &retrieved.signature {
            match openpgp::validate_signature(&self.options, context, signature, &retrieved) {
                Ok(()) => Ok(ValidatedAdvisory { retrieved }),
                Err(error) => Err(ValidationProcessError::Proceed(
                    ValidationError::Signature { error, retrieved },
                )),
            }
        } else {
            Ok(ValidatedAdvisory { retrieved })
        }
    }

    /// ensure that the digest matches if we have one
    fn validate_digest<D: Digest>(
        digest: &Option<RetrievedDigest<D>>,
    ) -> Result<(), (String, String)> {
        if let Some(digest) = &digest {
            digest.validate().map_err(|(s1, s2)| (s1.to_string(), s2))?;
        }
        Ok(())
    }
}

pub struct InnerValidationContext<VC> {
    context: VC,
    keys: Vec<PublicKey>,
}

#[async_trait(?Send)]
impl<V> RetrievedVisitor for ValidationVisitor<V>
where
    V: ValidatedVisitor,
{
    type Error = Error<V::Error>;
    type Context = InnerValidationContext<V::Context>;

    async fn visit_context(
        &self,
        context: &RetrievalContext,
    ) -> Result<Self::Context, Self::Error> {
        let keys = context.keys.clone();

        let context = self
            .visitor
            .visit_context(&ValidationContext {
                retrieval: &context,
            })
            .await
            .map_err(Error::Visitor)?;

        Ok(Self::Context { context, keys })
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        outcome: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        match outcome {
            Ok(advisory) => {
                let result = match self.validate(context, advisory).await {
                    Ok(result) => Ok(result),
                    Err(ValidationProcessError::Proceed(err)) => Err(err),
                    Err(ValidationProcessError::Abort(err)) => return Err(Error::Validation(err)),
                };
                self.visitor
                    .visit_advisory(&context.context, result)
                    .await
                    .map_err(Error::Visitor)?
            }
            Err(err) => self
                .visitor
                .visit_advisory(&context.context, Err(ValidationError::Retrieval(err)))
                .await
                .map_err(Error::Visitor)?,
        }

        Ok(())
    }
}
