#[cfg(feature = "cyclonedx-bom")]
pub mod cyclonedx;
#[cfg(feature = "serde-cyclonedx")]
pub mod serde_cyclonedx;
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
    #[cfg(feature = "cyclonedx-bom")]
    #[allow(irrefutable_let_patterns)]
    #[allow(deprecated)]
    if let Sbom::CycloneDx(sbom) = sbom {
        cyclonedx::all(report, sbom);
    }
    #[cfg(feature = "serde-cyclonedx")]
    #[allow(irrefutable_let_patterns)]
    if let Sbom::SerdeCycloneDx(sbom) = sbom {
        serde_cyclonedx::all(report, sbom);
    }
}
