use async_trait::async_trait;
use csaf::Csaf;
use std::borrow::Cow;

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> Result<(), Cow<'static, str>>;
}
