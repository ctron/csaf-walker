use crate::cmd::report::ReportSink;
use spdx_rs::models::SPDX;
use std::collections::{HashMap, HashSet};

/// Run all SPDX sbom checks
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
        self.duplicate_packages();
    }

    /// check for duplicate nodes
    fn duplicate_packages(&self) {
        let mut ids = HashMap::with_capacity(
            self.spdx.package_information.len() + self.spdx.file_information.len() + 1,
        );

        ids.insert(&self.spdx.document_creation_information.spdx_identifier, 1);

        for package in &self.spdx.package_information {
            *ids.entry(&package.package_spdx_identifier).or_default() += 1;
        }
        for file in &self.spdx.file_information {
            *ids.entry(&file.file_spdx_identifier).or_default() += 1;
        }

        for (id, num) in ids {
            if num > 1 {
                self.report
                    .error(format!("Duplicate SPDX ID '{id}', occurred {num} times."));
            }
        }
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
