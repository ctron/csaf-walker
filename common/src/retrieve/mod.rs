//! Retrieving remote content

use crate::utils::hex::Hex;
use digest::{Digest, Output};
use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};

/// The retrieved digest
#[derive(Clone, PartialEq, Eq)]
pub struct RetrievedDigest<D: Digest> {
    /// The expected digest, as read from the remote source
    pub expected: String,
    /// The actual digest, as calculated from reading the content
    pub actual: Output<D>,
}

impl<D: Digest> RetrievedDigest<D> {
    pub fn validate(&self) -> Result<(), (&str, String)> {
        let actual = Hex(&self.actual).to_lower();
        if self.expected == actual {
            Ok(())
        } else {
            Err((&self.expected, actual))
        }
    }
}

impl<D: Digest> Debug for RetrievedDigest<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetrievedDigest")
            .field("expected", &self.expected)
            .field("actual", &Hex(&self.actual))
            .finish()
    }
}

/// Building a digest while retrieving.
#[derive(Clone)]
pub struct RetrievingDigest<D: Digest> {
    pub expected: String,
    pub current: D,
}

impl<D> Deref for RetrievingDigest<D>
where
    D: Digest,
{
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.current
    }
}

impl<D> DerefMut for RetrievingDigest<D>
where
    D: Digest,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

impl<D> From<RetrievingDigest<D>> for RetrievedDigest<D>
where
    D: Digest,
{
    fn from(value: RetrievingDigest<D>) -> Self {
        Self {
            expected: value.expected,
            actual: value.current.finalize(),
        }
    }
}
