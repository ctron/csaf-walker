# CSAF Walker

"Walk" CSAF data from a remote server, allowing one to work with the data.

## From the command line

```shell
csaf download -3 -v -d out/ https://www.redhat.com/.well-known/csaf/provider-metadata.json
```

## In Rust

```rust
use anyhow::Result;
use url::Url;
use csaf_walker::source::HttpSource;
use csaf_walker::walker::Walker;
use csaf_walker::fetcher::Fetcher;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};

async fn walk() -> Result<()> {
  let fetcher = Fetcher::new(Default::default()).await?;
  let source = HttpSource {
    url: Url::parse("https://www.redhat.com/.well-known/csaf/provider-metadata.json")?,
    fetcher,
  };

  Walker::new(source.clone())
    .walk(RetrievingVisitor::new(
        source.clone(),
        ValidationVisitor::new(
            move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                log::info!("Found advisory: {advisory:?}");
                Ok::<_, anyhow::Error>(())
            },
        )
    ))
    .await?;

  Ok(())
}
```

## TODOs

* [ ] Support ROLIE
