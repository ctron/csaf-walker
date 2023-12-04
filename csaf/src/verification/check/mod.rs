use async_trait::async_trait;
use csaf::definitions::{BranchesT, ProductIdT};
use csaf::document::Category;
use csaf::product_tree::ProductTree;
use csaf::Csaf;
use std::borrow::Cow;
use std::collections::HashSet;

pub type CheckError = Cow<'static, str>;

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError>;
}

/// Implementation to allow a simple function style check
#[async_trait(?Send)]
impl<F> Check for F
where
    F: Fn(&Csaf) -> Vec<CheckError>,
{
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError> {
        (self)(csaf)
    }
}

#[derive(Debug, Default)]
pub struct Checking {
    results: Vec<CheckError>,
}

impl Checking {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn require(mut self, msg: impl Into<CheckError>, ok: bool) -> Self {
        if !ok {
            self.results.push(msg.into());
        }
        self
    }

    pub fn done(self) -> Vec<CheckError> {
        self.results
    }
}

/// /vulnerabilities needs to be more than one vulnerability listed
pub fn check_vulnerabilities_size(csaf: &Csaf) -> Vec<CheckError> {
    let result;
    if let Some(vs) = &csaf.vulnerabilities {
        result = vs.is_empty();
    } else {
        result = false;
    }
    Checking::new()
        .require("The csaf file's Vulnerabilities is empty", result)
        .done()
}
/// There needs at least one of
/// /vulnerabilities[]/product_status/fixed
/// /vulnerabilities[]/product_status/known_affected
/// /vulnerabilities[]/product_status/known_not_affected
/// /vulnerabilities[]/product_status/under_investigation
pub fn check_vulnerabilities_product_status(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = false;
    let checking = Checking::new();
    if let Some(vulns) = &csaf.vulnerabilities {
        for vuln in vulns {
            if let Some(product_status) = &vuln.product_status {
                result = product_status
                    .known_affected
                    .clone()
                    .is_some_and(|ps| ps.is_empty())
                    | product_status
                        .known_not_affected
                        .clone()
                        .is_some_and(|ps| ps.is_empty())
                    | product_status.fixed.clone().is_some_and(|ps| ps.is_empty())
                    | product_status
                        .first_fixed
                        .clone()
                        .is_some_and(|ps| ps.is_empty())
                    | product_status
                        .first_affected
                        .clone()
                        .is_some_and(|ps| ps.is_empty())
                    | product_status
                        .last_affected
                        .clone()
                        .is_some_and(|ps| ps.is_empty())
                    | product_status
                        .recommended
                        .clone()
                        .is_some_and(|ps| ps.is_empty())
                    | product_status
                        .under_investigation
                        .clone()
                        .is_some_and(|ps| ps.is_empty());
            }
        }
    }
    checking
        .require("The csaf does not have any vulnerabilities", !result)
        .done()
}

/// There needs at least one of
/// /vulnerabilities[]/cve
/// /vulnerabilities[]/ids
pub fn check_vulnerabilities_cve_ids(csaf: &Csaf) -> Vec<CheckError> {
    let mut result;
    let mut check_erroies = vec![];
    if let Some(vulns) = &csaf.vulnerabilities {
        for vuln in vulns {
            if let Some(ids) = &vuln.ids {
                result = ids.len() > 0;
            } else {
                result = false;
            }

            result = &vuln.cve.is_some() | result;

            if !result {
                if let Some(cwe) = &vuln.cwe {
                    check_erroies.extend(
                        Checking::new()
                            .require(
                                format!(
                                    "The vulnerability cwe id: {:?} does not have any cve or ids",
                                    &cwe.id
                                ),
                                result,
                            )
                            .done(),
                    );
                } else {
                    check_erroies.extend(
                        Checking::new()
                            .require(
                                format!("The csaf file have a  vulnerability"),
                                vuln.cve.is_none() | vuln.ids.is_none(),
                            )
                            .done(),
                    );
                }
            }
        }
    }
    check_erroies
}

fn get_all_product_id_from_product_tree_branches(
    branches: &BranchesT,
    products: &mut HashSet<String>,
) {
    for branch in &branches.0 {
        if let Some(product) = &branch.product {
            let id = &product.product_id;
            products.insert(id.clone().0);
        }
        if let Some(bs) = &branch.branches {
            get_all_product_id_from_product_tree_branches(&bs, products);
        }
    }
}

/// Verify product match within branches and relationships
pub fn check_branches_relationships_product_match(csaf: &Csaf) -> Vec<CheckError> {
    let mut result: Vec<CheckError> = vec![];
    if let Some(products_tree) = &csaf.product_tree {
        let mut names = HashSet::new();
        if let Some(branches) = &products_tree.branches {
            get_all_product_id_from_product_tree_branches(&branches, &mut names);
        }
        if let Some(relationships) = &products_tree.relationships {
            for r in relationships {
                result.extend(
                    Checking::new()
                        .require(
                            format!(
                        "There is no match for product {:?}  within branches and relationships.",
                        r.full_product_name.product_id
                    ),
                            names.contains(&r.product_reference.0)
                                && names.contains(&r.relates_to_product_reference.0),
                        )
                        .done(),
                );
            }
        }
    }
    result
}

fn get_all_product_names(product_tree: &ProductTree, products: &mut Vec<String>) {
    if let Some(relationships) = &product_tree.relationships {
        for r in relationships {
            let id = &r.full_product_name.product_id;
            products.push(id.clone().0);
        }
    }
}

fn check_product(
    product_names: &mut Vec<String>,
    product_id_t: &ProductIdT,
    erroies: &mut Vec<CheckError>,
) {
    erroies.extend(
        Checking::new()
            .require(
                format!("product {:?} does not exits in product tree", &product_id_t),
                product_names.contains(&product_id_t.0),
            )
            .done(),
    );
}

/// Verify that all vulnerabilities present in /vulnerabilities are also contained within product tree.
pub fn check_all_products_v11ies_exits_in_product_tree(csaf: &Csaf) -> Vec<CheckError> {
    let mut results = vec![];
    if let Some(products_tree) = &csaf.product_tree {
        let mut product_names = vec![];
        get_all_product_names(products_tree, &mut product_names);
        if let Some(v11y) = &csaf.vulnerabilities {
            for v in v11y {
                if let Some(product_status) = &v.product_status {
                    if let Some(product_its) = &product_status.known_affected {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.known_not_affected {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.fixed {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.first_fixed {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.first_affected {
                        for product in product_its {
                            check_product(&mut product_names, product.into(), &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.last_affected {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.recommended {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                    if let Some(product_its) = &product_status.under_investigation {
                        for product in product_its {
                            check_product(&mut product_names, product, &mut results);
                        }
                    }
                }
                if let Some(rs) = &v.remediations {
                    for remediation in rs {
                        if let Some(product_ids) = &remediation.product_ids {
                            for product_id in product_ids {
                                results.extend(
                                    Checking::new()
                                        .require(
                                            format!(
                                                "product {:?} does not exits in product tree",
                                                product_id.clone().0
                                            ),
                                            product_names.contains(&product_id.0),
                                        )
                                        .done(),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    results
}

/// Check revision history
pub fn check_history(csaf: &Csaf) -> Vec<CheckError> {
    Checking::new()
        .require(
            "Revision history must not be empty",
            !csaf.document.tracking.revision_history.is_empty(),
        )
        .done()
}

/// Verify VEX cattegory
pub fn check_csaf_vex(csaf: &Csaf) -> Vec<CheckError> {
    let result;
    match csaf.document.category {
        Category::Vex => result = true,
        _ => result = false,
    };
    Checking::new()
        .require("The document's category must be csaf_vex", result)
        .done()
}

pub fn init_vex_fmt_verifying_visitor() -> Vec<(&'static str, Box<dyn Check>)> {
    vec![
        (
            "check_vulnerabilities_size",
            Box::new(check_vulnerabilities_size),
        ),
        (
            "check_vulnerabilities_product_status",
            Box::new(check_vulnerabilities_product_status),
        ),
        (
            "check_vulnerabilities_cve_ids",
            Box::new(check_vulnerabilities_cve_ids),
        ),
        (
            "check_all_products_v11ies_exits_in_product_tree",
            Box::new(check_all_products_v11ies_exits_in_product_tree),
        ),
        ("check_history", Box::new(check_history)),
        ("check_csaf_vex", Box::new(check_csaf_vex)),
        (
            "check_branches_relationships_product_match",
            Box::new(check_branches_relationships_product_match),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use crate::verification::check::{
        check_all_products_v11ies_exits_in_product_tree,
        check_branches_relationships_product_match, check_csaf_vex, check_history,
        check_vulnerabilities_cve_ids, check_vulnerabilities_product_status,
        check_vulnerabilities_size,
    };
    use csaf::Csaf;

    /// Verify notexits-7ComputeNode-7.7.EUS:microcode_ctl-2:2.1-53.18.el7_7.src does not exits in product tree
    #[tokio::test]
    async fn test_check_all_products_v11ies_exits_in_product_tree() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2021_3029.json")).unwrap();
        assert_eq!(
            check_all_products_v11ies_exits_in_product_tree(&csaf)
                .first()
                .unwrap()
                .contains("notexits"),
            true
        )
    }

    #[tokio::test]
    async fn test_check_csaf_vex() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2021_3029.json")).unwrap();
        assert_eq!(check_csaf_vex(&csaf).len(), 1);
    }

    #[tokio::test]
    async fn test_check_history() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2021_3029.json")).unwrap();
        assert_eq!(check_history(&csaf).len(), 0);
    }

    /// Verify the csaf file does not have any vulnerabilities
    #[tokio::test]
    async fn test_check_vulnerabilities_product_status() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2023_1441.json")).unwrap();
        assert_eq!(check_vulnerabilities_product_status(&csaf).len(), 1);
    }

    /// Verify the csaf's vulnerabilities does not have cve and ids
    #[tokio::test]
    async fn test_check_vulnerabilities_cve_ids() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2023_1441.json")).unwrap();
        assert_eq!(
            check_vulnerabilities_cve_ids(&csaf)
                .first()
                .unwrap()
                .contains("CWE-704"),
            true
        );
    }

    /// Verify the csaf file does not have any vulnerabilities
    #[tokio::test]
    async fn test_check_vulnerabilities_size() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2023_3408.json")).unwrap();
        assert_eq!(check_vulnerabilities_size(&csaf).len(), 1);
    }

    /// Verify product do not match in branches and relationships
    #[tokio::test]
    async fn test_branches_relationships_product_match() {
        let csaf: Csaf =
            serde_json::from_str(include_str!("../../../test-data/rhsa-2023_4378.json")).unwrap();
        assert_eq!(
            check_branches_relationships_product_match(&csaf)
                .first()
                .unwrap()
                .contains(
                    "notmatch-NFV-9.2.0.Z.MAIN.EUS:kernel-rt-0:5.14.0-284.25.1.rt14.310.el9_2.src"
                ),
            true
        );
    }
}
