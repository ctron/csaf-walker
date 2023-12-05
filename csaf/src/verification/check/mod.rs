use async_trait::async_trait;
use csaf::Csaf;
use std::borrow::Cow;

pub mod base;
pub mod vex;

pub type CheckError = Cow<'static, str>;

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError>;
}

/// Implementation to allow a simple function style check
#[async_trait(?Send)]
impl<F> Check for F
where
    F: Fn(&Csaf) -> Vec<CheckError>,
{
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError> {
        (self)(csaf)
    }
}

#[derive(Debug, Default)]
pub struct Checking {
    results: Vec<CheckError>,
}

impl Checking {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn require(mut self, msg: impl Into<CheckError>, ok: bool) -> Self {
        if !ok {
            self.results.push(msg.into());
        }
        self
    }

    pub fn done(self) -> Vec<CheckError> {
        self.results
    }
}
