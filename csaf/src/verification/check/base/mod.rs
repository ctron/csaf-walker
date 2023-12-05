use csaf::Csaf;
// use csaf::document::{Category, CsafVersion, PublisherCategory};
use crate::verification::check::{Check, CheckError, Checking};

pub fn check_csaf_base(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = vec![];
    result.extend(
        Checking::new()
            .require(
                "The csaf file does not have document publisher name",
                !csaf.document.publisher.name.is_empty(),
            )
            .done(),
    );
    result.extend(
        Checking::new()
            .require(
                "The csaf file does not have document title",
                !csaf.document.title.is_empty(),
            )
            .done(),
    );
    result.extend(
        Checking::new()
            .require(
                "The csaf file's document tracking id is empty",
                !csaf.document.tracking.id.is_empty(),
            )
            .done(),
    );
    result
}

pub fn check_csaf_document_tracking_revision_history(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = vec![];
    for revision in &csaf.document.tracking.revision_history {
        result.extend(
            Checking::new()
                .require(
                    format!(
                        "The csaf file's document revision_history {:?} number is empty",
                        revision.number.to_string()
                    ),
                    !revision.number.is_empty(),
                )
                .done(),
        );
        result.extend(
            Checking::new()
                .require(
                    "The csaf file's document revision_history summary is empty",
                    !revision.summary.is_empty(),
                )
                .done(),
        );
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
// pub fn check_csaf_publisher_category(csaf: &Csaf) -> Vec<CheckError> {
//     let result;
//     match csaf.document.publisher.category {
//         PublisherCategory::Vendor => result = false,
//         PublisherCategory::Coordinator => result = false,
//         PublisherCategory::Other => result = false,
//         PublisherCategory::Discoverer => result = false,
//         PublisherCategory::Translator => result = false,
//         PublisherCategory::User => result = false,
//         _ => result = false,
//     }
//     Checking::new().require("The csaf's document publisher category is not right", result).done()
// }
//
// pub fn check_csaf_category(csaf: &Csaf) -> Vec<CheckError> {
//     let result;
//     match csaf.document.category {
//         Category::Vex => result = true,
//         Category::Base => result = true,
//         Category::SecurityAdvisory => result = true,
//         _ => result = false,
//     };
//     Checking::new().require("The csaf's document category is not right", result).done()
// }
//
// pub fn check_csaf_version(csaf: &Csaf) -> Vec<CheckError> {
//     let result;
//     match csaf.document.csaf_version {
//         CsafVersion::TwoDotZero =>result = true,
//         _ => result = false,
//     };
//     Checking::new().require("The csaf's version is not right", result).done()
// }

#[cfg(test)]
mod tests {
    use crate::verification::check::base::{
        check_csaf_base, check_csaf_document_tracking_revision_history,
    };
    use csaf::Csaf;

    #[tokio::test]
    async fn test_check_csaf_base() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../../test-data/rhsa-2021_3029.json"))
                .unwrap();
        assert_eq!(check_csaf_base(&csaf).len(), 3)
    }

    #[tokio::test]
    async fn test_check_csaf_document_tracking_revision_history() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../../test-data/rhsa-2021_3029.json"))
                .unwrap();
        assert_eq!(
            check_csaf_document_tracking_revision_history(&csaf).len(),
            1
        )
    }
}
