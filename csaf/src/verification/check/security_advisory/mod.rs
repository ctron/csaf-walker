use crate::verification::{
    check::vex::check_all_products_v11ies_exits_in_product_tree, check::Check,
};

pub fn init_csaf_security_advisory_verifying_visitor() -> Vec<(&'static str, Box<dyn Check>)> {
    vec![(
        "check_all_products_v11ies_exits_in_product_tree",
        Box::new(check_all_products_v11ies_exits_in_product_tree),
    )]
}
