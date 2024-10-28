//! Validation

use crate::{
    discover::{AsDiscovered, DiscoveredAdvisory},
    retrieve::{
        AsRetrieved, RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor,
    }
};
use digest::Digest;
use std::{
    fmt::{Debug, Display, Formatter},
    future::Future,
    ops::{Deref, DerefMut}
};
use url::Url;
use walker_common::{
    retrieve::RetrievedDigest,
    utils::{
        openpgp::PublicKey,
        url::Urlify
    },
    validate::{openpgp, ValidationOptions},
};

/// A validated CSAF document
///
/// This includes
/// * The document could be retrieved
/// * The digest matches or was absent
/// * The signature was valid
#[derive(Clone, Debug)]
pub struct ValidatedAdvisory {
    /// The retrieved advisory
    pub retrieved: RetrievedAdvisory,
}

impl Urlify for ValidatedAdvisory {
    fn url(&self) -> &Url {
        &self.url
    }

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        self.retrieved.relative_base_and_url()
    }
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

impl AsDiscovered for ValidatedAdvisory {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        &self.discovered
    }
}

impl AsRetrieved for ValidatedAdvisory {
    fn as_retrieved(&self) -> &RetrievedAdvisory {
        &self.retrieved
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

impl AsDiscovered for ValidationError {
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        match self {
            Self::Retrieval(err) => err.discovered(),
            Self::DigestMismatch { retrieved, .. } => retrieved.as_discovered(),
            Self::Signature { retrieved, .. } => retrieved.as_discovered(),
        }
    }
}

impl Urlify for ValidationError {
    fn url(&self) -> &Url {
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
                retrieved: _,
            } => write!(
                f,
                "Digest mismatch - expected: {expected}, actual: {actual}",
            ),
            Self::Signature {
                error,
                retrieved: _,
            } => {
                write!(f, "Invalid signature: {error}",)
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
        self.retrieval
    }
}

pub trait ValidatedVisitor {
    type Error: Display + Debug;
    type Context;

    fn visit_context(
        &self,
        context: &ValidationContext,
    ) -> impl Future<Output = Result<Self::Context, Self::Error>>;

    fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}

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
        _context: &ValidationContext<'_>,
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
    /// Returning either a processing error, or a result which will be forwarded to the visitor.
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
            match openpgp::validate_signature(
                &self.options,
                &context.keys,
                signature,
                &retrieved.data,
            ) {
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

impl<V> RetrievedVisitor for ValidationVisitor<V>
where
    V: ValidatedVisitor,
{
    type Error = Error<V::Error>;
    type Context = InnerValidationContext<V::Context>;

    async fn visit_context(
        &self,
        context: &RetrievalContext<'_>,
    ) -> Result<Self::Context, Self::Error> {
        let keys = context.keys.clone();

        let context = self
            .visitor
            .visit_context(&ValidationContext { retrieval: context })
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
