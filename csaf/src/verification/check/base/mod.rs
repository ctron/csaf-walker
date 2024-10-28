use crate::verification::check::{Check, CheckError, Checking};
use csaf::Csaf;

pub fn check_csaf_base(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = vec![];
    result.extend(
        Checking::new()
            .require(
                "The CSAF file does not have a document publisher name",
                !csaf.document.publisher.name.is_empty(),
            )
            .require(
                "The CSAF file does not have a document title",
                !csaf.document.title.is_empty(),
            )
            .require(
                "The CSAF file's document tracking id is empty",
                !csaf.document.tracking.id.is_empty(),
            )
            .done(),
    );
    result
}

pub fn check_csaf_document_tracking_revision_history(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = vec![];
    let mut most_recent = None;
    for revision in &csaf.document.tracking.revision_history {
        result.extend(
            Checking::new()
                .require(
                    format!(
                        "The CSAF file's document revision_history {:?} number is empty",
                        revision.number.to_string()
                    ),
                    !revision.number.is_empty(),
                )
                .require(
                    "The CSAF file's document revision_history summary is empty",
                    !revision.summary.is_empty(),
                )
                .done(),
        );

        match most_recent {
            None => {
                most_recent = Some((revision.date, &revision.number));
            }
            Some((date, _)) if date < revision.date => {
                most_recent = Some((revision.date, &revision.number));
            }
            _ => {}
        }
    }

    if let Some((_, version)) = most_recent {
        result.extend(
            Checking::new()
                .require(
                    format!(
                        "The CSAF tracking version ({}) must be equal to the most recent version ({}).",
                        csaf.document.tracking.version,
                        version,
                    ),
                    version.as_str() == csaf.document.tracking.version)
                .done(),
        )
    }

    result
}

pub fn init_csaf_base_verifying_visitor() -> Vec<(&'static str, Box<dyn Check>)> {
    vec![
        ("check_csaf_base", Box::new(check_csaf_base)),
        (
            "check_csaf_document_tracking_revision_history",
            Box::new(check_csaf_document_tracking_revision_history),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use crate::verification::check::base::{
        check_csaf_base, check_csaf_document_tracking_revision_history,
    };
    use csaf::Csaf;

    #[tokio::test]
    async fn test_check_csaf_base() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../../test-data/rhba-2023_0564.json"))
                .expect("example data must parse");
        assert_eq!(check_csaf_base(&csaf).len(), 3)
    }

    #[tokio::test]
    async fn test_check_csaf_document_tracking_revision_history() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../../test-data/rhba-2023_0564.json"))
                .expect("example data must parse");
        assert_eq!(
            check_csaf_document_tracking_revision_history(&csaf).len(),
            2
        )
    }
}
