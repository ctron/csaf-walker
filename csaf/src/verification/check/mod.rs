use async_trait::async_trait;
use csaf::Csaf;
use std::borrow::Cow;
use std::collections::HashSet;
use csaf::product_tree::ProductTree;

pub type CheckError = Cow<'static, str>;

#[async_trait(?Send)]
pub trait Check {
    /// Perform a check on a CSAF document
    async fn check(&self, csaf: &Csaf) -> Vec<CheckError>;
}

// Implementation to allow a simple function style check
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

pub fn check_VEX_fmt(csaf: &Csaf) -> Vec<CheckError> {
    Checking::new()
        .require(
            "Revision history must not be empty",
            !csaf.document.tracking.revision_history.is_empty(),
        )
        .done()
}

pub fn check_vulnerabilities_size(csaf: &Csaf) -> Vec<CheckError> {
    Checking::new()
        .require("Vulnerabilities is empty", csaf.vulnerabilities.is_some())
        .done()
}

pub fn check_vulnerabilities_product_status(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = false;
    let checking = Checking::new();
    if let Some(vulns) = &csaf.vulnerabilities {
        for vuln in vulns {
            if let Some(product_status) = &vuln.product_status {
                result = product_status.known_affected.is_some()
                    | product_status.known_not_affected.is_some()
                    | product_status.fixed.is_some()
                    | product_status.first_fixed.is_some()
                    | product_status.first_affected.is_some()
                    | product_status.last_affected.is_some()
                    | product_status.recommended.is_some()
                    | product_status.under_investigation.is_some();
            }
        }
    }
    checking.require("The csaf does not have any vulnerabilities", result).done()
}

pub fn check_vulnerabilities_cve_ids(csaf: &Csaf) -> Vec<CheckError> {
    let mut result = false;
    if let Some(vulns) = &csaf.vulnerabilities {
        for vuln in vulns {
            result = vuln.cve.is_some() | vuln.ids.is_some();
        }
    }
    Checking::new().require("The csaf does not have any cve or ids", result).done()
}

pub fn check_all_products_exits_in_v11ies(csaf: &Csaf) -> Vec<CheckError> {
    if let Some(products_tree) = &csaf.product_tree {
        if let Some(names) = &products_tree.full_product_names {
            for name in names {
                let mut b: bool = false;
                if let Some(v11y) = &csaf.vulnerabilities {
                    for v in v11y {
                        if let Some(product_status) = &v.product_status {
                            if let Some(product_its) = &product_status.known_affected {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.known_not_affected {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.fixed {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.first_fixed {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.first_affected {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.last_affected {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.recommended {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            if let Some(product_its) = &product_status.under_investigation {
                                for product in product_its {
                                    if name.name == product.0 {
                                        b = b | true;
                                    }
                                }
                            }
                            return Checking::new().require(format!("product {:?} do not have any v11y", name), b).done();
                        }
                    }
                };
            }
        }else {

        }
    }
    Checking::new().require(format!("all product is ok"), true).done()
}

pub fn check_history(csaf: &Csaf) -> Vec<CheckError> {
    Checking::new()
        .require(
            "Revision history must not be empty",
            !csaf.document.tracking.revision_history.is_empty(),
        )
        .done()
}

#[cfg(test)]
mod tests {
    use csaf::Csaf;
    use crate::verification::check::{check_all_products_exits_in_v11ies, check_history};

    fn loadCsaf() -> Csaf {
        // let data = std::fs::read("../mock-data/config.json").unwrap();
        let csaf: Csaf = serde_json::from_str(include_str!("../../../mock-data/rhsa-2021_3029.json")).unwrap();
        csaf
    }
    #[tokio::test]
    async fn test_check_history() {
        let csaf = loadCsaf();
        check_all_products_exits_in_v11ies(&csaf);
    }
}