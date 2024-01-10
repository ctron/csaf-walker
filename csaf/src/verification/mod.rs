//! Verification
//!
//! Checks to ensure conformity with the specification.

use crate::discover::{AsDiscovered, DiscoveredAdvisory};
use crate::retrieve::{
    AsRetrieved, RetrievalContext, RetrievalError, RetrievedAdvisory, RetrievedVisitor,
};
use crate::validation::{ValidatedAdvisory, ValidatedVisitor, ValidationContext, ValidationError};
use crate::verification::check::{Check, CheckError};
use async_trait::async_trait;
use csaf::Csaf;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use url::Url;
use walker_common::utils::url::Urlify;

pub mod check;

#[derive(Debug)]
pub struct VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
{
    pub advisory: A,
    pub csaf: Csaf,
    pub failures: HashMap<I, Vec<CheckError>>,
    pub successes: HashSet<I>,
}

impl<A, I> Deref for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
{
    type Target = A;

    fn deref(&self) -> &Self::Target {
        &self.advisory
    }
}

impl<A, I> DerefMut for VerifiedAdvisory<A, I>
where
    A: AsRetrieved,
    I: Clone + PartialEq + Eq + Hash,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.advisory
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError<UE, A>
where
    A: Debug,
    UE: Display + Debug,
{
    #[error(transparent)]
    Upstream(UE),
    #[error("document parsing error: {error}")]
    Parsing {
        advisory: A,
        error: serde_json::Error,
    },
}

impl<A, UE> AsDiscovered for VerificationError<UE, A>
where
    A: AsDiscovered + Debug,
    UE: AsDiscovered + Display + Debug,
{
    fn as_discovered(&self) -> &DiscoveredAdvisory {
        match self {
            Self::Upstream(err) => err.as_discovered(),
            Self::Parsing { advisory, .. } => advisory.as_discovered(),
        }
    }
}

impl<UE, A> Urlify for VerificationError<UE, A>
where
    A: AsRetrieved + Debug,
    UE: Urlify + Display + Debug,
{
    fn url(&self) -> &Url {
        match self {
            Self::Upstream(err) => err.url(),
            Self::Parsing { advisory, .. } => advisory.as_retrieved().url(),
        }
    }
}

pub struct VerificationContext {}

/// A visitor accepting a verified advisory
#[async_trait(?Send)]
pub trait VerifiedVisitor<A, E, I>
where
    A: AsRetrieved,
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
{
    type Error: Display + Debug;
    type Context;

    async fn visit_context(
        &self,
        context: &VerificationContext,
    ) -> Result<Self::Context, Self::Error>;

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<VerifiedAdvisory<A, I>, VerificationError<E, A>>,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error<VE>
where
    VE: Display + Debug,
{
    #[error(transparent)]
    Visitor(VE),
}

/// A visitor implementing the verification of a CSAF document
pub struct VerifyingVisitor<A, E, V, I>
where
    A: AsRetrieved,
    V: VerifiedVisitor<A, E, I>,
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
{
    visitor: V,
    checks: Vec<(I, Box<dyn Check>)>,
    _marker: PhantomData<(A, E)>,
}

impl<A, E, V, I> VerifyingVisitor<A, E, V, I>
where
    A: AsRetrieved,
    V: VerifiedVisitor<A, E, I>,
    E: Display + Debug,
    I: Clone + PartialEq + Eq + Hash,
{
    pub fn new(visitor: V) -> Self {
        Self {
            visitor,
            checks: vec![],
            _marker: Default::default(),
        }
    }

    pub fn with_checks(visitor: V, checks: Vec<(I, Box<dyn Check>)>) -> Self {
        Self {
            visitor,
            checks,
            _marker: Default::default(),
        }
    }

    pub fn add<F: Check + 'static>(mut self, index: I, check: F) -> Self {
        self.checks.push((index, Box::new(check)));
        self
    }

    async fn verify(&self, advisory: A) -> Result<VerifiedAdvisory<A, I>, VerificationError<E, A>> {
        let csaf: Csaf = match serde_json::from_slice(&advisory.as_retrieved().data) {
            Ok(csaf) => csaf,
            Err(error) => return Err(VerificationError::Parsing { error, advisory }),
        };

        let mut failures = HashMap::new();
        let mut successes = HashSet::new();

        for (index, check) in &self.checks {
            let result = check.as_ref().check(&csaf).await;
            if !result.is_empty() {
                failures.insert(index.clone(), result);
            } else {
                successes.insert(index.clone());
            }
        }

        Ok(VerifiedAdvisory {
            advisory,
            csaf,
            failures,
            successes,
        })
    }
}

#[async_trait(?Send)]
impl<V, I> RetrievedVisitor for VerifyingVisitor<RetrievedAdvisory, RetrievalError, V, I>
where
    V: VerifiedVisitor<RetrievedAdvisory, RetrievalError, I>,
    I: Clone + PartialEq + Eq + Hash,
{
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        _context: &RetrievalContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(&VerificationContext {})
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<RetrievedAdvisory, RetrievalError>,
    ) -> Result<(), Self::Error> {
        let result = match result {
            Ok(doc) => self.verify(doc).await,
            Err(err) => Err(VerificationError::Upstream(err)),
        };

        self.visitor
            .visit_advisory(context, result)
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<V, I> ValidatedVisitor for VerifyingVisitor<ValidatedAdvisory, ValidationError, V, I>
where
    V: VerifiedVisitor<ValidatedAdvisory, ValidationError, I>,
    I: Clone + PartialEq + Eq + Hash,
{
    type Error = Error<V::Error>;
    type Context = V::Context;

    async fn visit_context(
        &self,
        _context: &ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.visitor
            .visit_context(&VerificationContext {})
            .await
            .map_err(Error::Visitor)
    }

    async fn visit_advisory(
        &self,
        context: &Self::Context,
        result: Result<ValidatedAdvisory, ValidationError>,
    ) -> Result<(), Self::Error> {
        let result = match result {
            Ok(doc) => self.verify(doc).await,
            Err(err) => Err(VerificationError::Upstream(err)),
        };

        self.visitor
            .visit_advisory(context, result)
            .await
            .map_err(Error::Visitor)?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl<F, E, Fut, A, I, UE> VerifiedVisitor<A, UE, I> for F
where
    UE: Debug + Display + 'static,
    F: Fn(Result<VerifiedAdvisory<A, I>, VerificationError<UE, A>>) -> Fut,
    Fut: Future<Output = Result<(), E>>,
    E: Display + Debug + 'static,
    A: AsRetrieved + 'static,
    I: Clone + PartialEq + Eq + Hash + 'static,
{
    type Error = E;
    type Context = ();

    async fn visit_context(
        &self,
        _context: &VerificationContext,
    ) -> Result<Self::Context, Self::Error> {
        Ok(())
    }

    async fn visit_advisory(
        &self,
        _ctx: &Self::Context,
        outcome: Result<VerifiedAdvisory<A, I>, VerificationError<UE, A>>,
    ) -> Result<(), Self::Error> {
        self(outcome).await
    }
}
