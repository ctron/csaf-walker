use anyhow::Result;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::source::HttpSource;
use csaf_walker::walker::Walker;
use url::Url;
use csaf_walker::verification::{VerificationError, VerifiedAdvisory, VerifiedVisitor, VerifyingVisitor};
use csaf_walker::verification::check::{check_all_products_exits_in_v11ies, check_history, check_vulnerabilities_cve_ids, check_vulnerabilities_product_status, check_vulnerabilities_size};
use walker_common::fetcher::Fetcher;

#[tokio::main]
async fn main() {
    walk().await;
}

async fn walk() -> Result<()> {
    let fetcher = Fetcher::new(Default::default()).await?;
    let source = HttpSource {
        url: Url::parse("https://www.redhat.com/.well-known/csaf/provider-metadata.json")?,
        options: Default::default(),
        fetcher,
    };

    Walker::new(source.clone())
        .walk(RetrievingVisitor::new(
            source.clone(),
            VerifyingVisitor::new(
                move |advisory: Result<VerifiedAdvisory<_, _>, VerificationError<_, _>>| async move {
                    log::info!("Found advisory: {advisory:?}");
                    Ok::<_, anyhow::Error>(())
                }).add("check_history", check_history).add("check_all_products_exits_in_v11ies", check_all_products_exits_in_v11ies)
                .add("check_vulnerabilities_cve_ids", check_vulnerabilities_cve_ids).add("check_vulnerabilities_product_status", check_vulnerabilities_product_status)
                .add("check_vulnerabilities_size", check_vulnerabilities_size)
        ))
        .await?;

    Ok(())
}
