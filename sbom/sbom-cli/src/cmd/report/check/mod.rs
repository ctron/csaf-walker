mod spdx;

use crate::cmd::report::ReportSink;
use sbom_walker::Sbom;

/// Run all SBOM checks
pub fn all(report: &dyn ReportSink, sbom: Sbom) {
    if let Sbom::Spdx(sbom) = sbom {
        spdx::all(report, sbom)
    }
}
