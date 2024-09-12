#[cfg(feature = "spdx-rs")]
pub mod spdx;

use super::ReportSink;
use crate::Sbom;

/// Run all SBOM checks
pub fn all(#[allow(unused)] report: &dyn ReportSink, #[allow(unused)] sbom: &Sbom) {
    #[cfg(feature = "spdx-rs")]
    #[allow(irrefutable_let_patterns)]
    if let Sbom::Spdx(sbom) = sbom {
        spdx::all(report, sbom);
    }
}
