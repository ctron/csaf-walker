use crate::report::ReportSink;
use serde_cyclonedx::cyclonedx::v_1_6::CycloneDx;
use std::collections::HashMap;

/// Run all SPDX sbom checks
pub fn all(report: &dyn ReportSink, sbom: &CycloneDx) {
    CycloneDxChecks { report, sbom }.all();
}

struct CycloneDxChecks<'c> {
    report: &'c dyn ReportSink,
    sbom: &'c CycloneDx,
}

impl CycloneDxChecks<'_> {
    /// Run all checks
    pub fn all(&self) {
        log::debug!("Running all CycloneDX checks");

        self.duplicate_components();
        self.missing_bom_refs();
    }

    fn collect_bom_refs(&self) -> HashMap<&str, usize> {
        let mut bom_refs = HashMap::<_, usize>::new();

        for component in self.sbom.components.iter().flatten() {
            if let Some(bom_ref) = &component.bom_ref {
                *bom_refs.entry(bom_ref.as_str()).or_default() += 1;
            }
        }

        bom_refs
    }

    /// Ensure that all bom-refs are unique.
    ///
    /// > An optional identifier which can be used to reference the component elsewhere in the BOM. Every bom-ref MUST be unique within the BOM.
    pub fn duplicate_components(&self) {
        log::debug!("Checking component duplicates");

        let bom_refs = self.collect_bom_refs();

        for (bom_ref, num) in bom_refs {
            if num > 1 {
                self.report.error(format!(
                    "Duplicate bom-ref '{bom_ref}', occurred {num} times."
                ));
            }
        }
    }

    /// Ensure that all bom-refs are present.
    pub fn missing_bom_refs(&self) {
        log::debug!("Check for missing bom-ref targets");

        let bom_refs = self.collect_bom_refs();

        for deps in self.sbom.dependencies.iter().flatten() {
            if !bom_refs.contains_key(&*deps.ref_) {
                self.report.error(format!(
                    "Missing left-side dependency reference: {}",
                    deps.ref_
                ));
            }
            for right in deps.depends_on.iter().flatten() {
                if !bom_refs.contains_key(right.as_str()) {
                    self.report
                        .error(format!("Missing right-side dependency reference: {right}",));
                }
            }
        }
    }
}
