use crate::model::metadata::Distribution;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use std::path::{Path, PathBuf};

/// create a distribution base directory
pub fn distribution_base(base: impl AsRef<Path>, distribution: &Distribution) -> PathBuf {
    base.as_ref().join(
        utf8_percent_encode(distribution.directory_url.as_str(), NON_ALPHANUMERIC).to_string(),
    )
}
