use crate::verification::check::{
    security_incident_response::{check_csaf_document_notes, check_csaf_document_references},
    Check, CheckError, Checking,
};
use csaf::Csaf;

pub fn check_vulnerabilities_not_exits(csaf: &Csaf) -> Vec<CheckError> {
    if is_informational_advisory(csaf) {
        return vec![];
    }
    Checking::new()
        .require(
            "The CSAF file should not relate to a vulnerability ",
            csaf.vulnerabilities.is_some(),
        )
        .done()
}

pub fn is_informational_advisory(csaf: &Csaf) -> bool {
    csaf.document.category.to_string() == "csaf_informational_advisory"
}

pub fn init_csaf_informational_advisory_verifying_visitor() -> Vec<(&'static str, Box<dyn Check>)> {
    vec![
        (
            "check_vulnerabilities_not_exits",
            Box::new(check_vulnerabilities_not_exits),
        ),
        (
            "check_csaf_document_notes",
            Box::new(check_csaf_document_notes),
        ),
        (
            "check_csaf_document_references",
            Box::new(check_csaf_document_references),
        ),
    ]
}
