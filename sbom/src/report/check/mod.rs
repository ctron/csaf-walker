#[cfg(feature = "spdx-rs")]
pub mod spdx;

use super::ReportSink;
use crate::Sbom;

/// Run all SBOM checks
pub fn all(report: &dyn ReportSink, sbom: Sbom) {
    #[cfg(feature = "spdx-rs")]
    if let Sbom::Spdx(sbom) = sbom {
        spdx::all(report, sbom)
    }
}
