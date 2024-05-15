use crate::cmd::report::ReportSink;
use spdx_rs::models::SPDX;
use std::collections::HashSet;

pub fn all(report: &dyn ReportSink, spdx: SPDX) {
    SpdxChecks {
        report,
        spdx: &spdx,
    }
    .all();
}

struct SpdxChecks<'c> {
    report: &'c dyn ReportSink,
    spdx: &'c SPDX,
}

impl SpdxChecks<'_> {
    pub fn all(&self) {
        self.rel_targets();
    }

    /// check if all relationships have valid targets
    fn rel_targets(&self) {
        let mut ids = self
            .spdx
            .package_information
            .iter()
            .map(|p| &p.package_spdx_identifier)
            .collect::<HashSet<_>>();

        ids.insert(&self.spdx.document_creation_information.spdx_identifier);

        // now see if all relationships have valid targets

        for rel in &self.spdx.relationships {
            if !ids.contains(&rel.spdx_element_id) {
                self.report.error(format!(
                    "Invalid reference '{left}' of relationship '{left}' -[{rel:?}]-> '{right}'",
                    left = rel.spdx_element_id,
                    rel = rel.relationship_type,
                    right = rel.related_spdx_element
                ));
            }
            if !ids.contains(&rel.related_spdx_element) {
                self.report.error(format!(
                    "Invalid reference '{right}' of relationship '{left}' -[{rel:?}]-> '{right}'",
                    left = rel.spdx_element_id,
                    rel = rel.relationship_type,
                    right = rel.related_spdx_element
                ));
            }
        }
    }
}
