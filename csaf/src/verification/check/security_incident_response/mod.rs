use crate::verification::check::{Check, CheckError, Checking};
use csaf::{
    definitions::{NoteCategory, ReferenceCategory},
    Csaf,
};

pub fn check_csaf_document_notes(csaf: &Csaf) -> Vec<CheckError> {
    if !is_security_incident_response(csaf) && !is_security_informational_advisory(csaf) {
        return vec![];
    }
    let mut result = false;
    if let Some(notes) = &csaf.document.notes {
        for note in notes {
            let mut is_invalid_note = false;
            match note.category {
                NoteCategory::Description => is_invalid_note |= true,
                NoteCategory::Details => is_invalid_note |= true,
                NoteCategory::Summary => is_invalid_note |= true,
                NoteCategory::General => is_invalid_note |= true,
                _ => is_invalid_note |= false,
            }
            result |= is_invalid_note;
        }
    }
    Checking::new().require("The document note with at least one item which has a category of description, details, general or summary", result).done()
}

pub fn check_csaf_document_references(csaf: &Csaf) -> Vec<CheckError> {
    if !is_security_incident_response(csaf) && !is_security_informational_advisory(csaf) {
        return vec![];
    }
    let mut result = false;
    if let Some(references) = &csaf.document.references {
        for reference in references {
            if let Some(category) = &reference.category {
                match category {
                    ReferenceCategory::External => result |= true,
                    ReferenceCategory::RefSelf => result |= false,
                }
            }
        }
    }
    Checking::new()
        .require(
            "The document references with at least one item which has a category of external",
            result,
        )
        .done()
}

pub fn is_security_incident_response(csaf: &Csaf) -> bool {
    csaf.document.category.to_string() == "csaf_security_incident_response"
}

pub fn is_security_informational_advisory(csaf: &Csaf) -> bool {
    csaf.document.category.to_string() == "csaf_security_informational_advisory"
}

pub fn init_csaf_is_security_incident_response_verifying_visitor(
) -> Vec<(&'static str, Box<dyn Check>)> {
    vec![
        (
            "check_csaf_document_notes",
            Box::new(check_csaf_document_notes),
        ),
        (
            "check_csaf_document_tracking_revision_history",
            Box::new(check_csaf_document_references),
        ),
    ]
}
