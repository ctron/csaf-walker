use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::path::{Path, PathBuf};

/// create a distribution base directory
pub fn distribution_base(base: impl AsRef<Path>, url: &str) -> PathBuf {
    base.as_ref()
        .join(utf8_percent_encode(url, NON_ALPHANUMERIC).to_string())
}
