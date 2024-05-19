use csaf_walker::{
    common::fetcher::{Fetcher, FetcherOptions},
    retrieve::RetrievingVisitor,
    source::{HttpOptions, HttpSource},
    validation::ValidationVisitor,
    walker::Walker,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fetcher = Fetcher::new(FetcherOptions::default()).await?;
    let source = HttpSource::new("redhat.com", fetcher, HttpOptions::default());

    let validator = ValidationVisitor::new(|result| async {
        match result {
            Ok(doc) => println!("Document: {doc:?}"),
            Err(err) => println!("Failed: {err}"),
        }
        Ok::<_, anyhow::Error>(())
    });
    let retriever = RetrievingVisitor::new(source.clone(), validator);

    Walker::new(source).walk(retriever).await?;

    Ok(())
}
