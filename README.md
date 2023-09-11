# CSAF Walker

"Walk" CSAF data from a remote server, allowing one to work with the data.

## From the command line

There's a command line tool, which can be used right away.

### Installation

```shell
cargo install csaf-cli
```

### Usage

You can download all documents be providing a link to the metadata endpoint:

```shell
csaf download -3 -v -d out/ https://www.redhat.com/.well-known/csaf/provider-metadata.json
```

It is also possible to only download validated files:

```shell
csaf sync -3 -v -d out/ https://www.redhat.com/.well-known/csaf/provider-metadata.json
```

### Differential sync

By default, timestamps reported by the HTTP server will be applied to the downloaded files. When re-running, the
`changes.csv` file will be used as a source to discover when a file was changed. If a file is already present and has
a newer modification timestamp in the `changes.csv` file, then it will be downloaded again. Otherwise, it will be
skipped.

Using the `--since` option, it is possible to provide a start timestamp, which will skip all changes reported before
this timestamp, and force all changes after this timestamp (independent of the file local file timestamp) to be
re-synced.

Using the `--since-file` option, it is possible to automate the "since" value, by initially loading the "since" value
from a file, and storing it into a file at the end of a successful run. The timestamp stored will be the timestamp,
when the application started processing.

If both `--since` and `--since-file` are provided, then the "since file" will be used first, and the "since" value will
act as a fallback if the file is not present.

## As a library

Using the crate `csaf-walker`, this can also be used as a library:

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
