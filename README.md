# CSAF Walker

[![crates.io](https://img.shields.io/crates/v/csaf-walker.svg)](https://crates.io/crates/csaf-walker)
[![docs.rs](https://docs.rs/csaf-walker/badge.svg)](https://docs.rs/csaf-walker)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/tag/ctron/csaf-walker?sort=semver)](https://github.com/ctron/csaf-walker/releases)
[![CI](https://github.com/ctron/csaf-walker/workflows/CI/badge.svg)](https://github.com/ctron/csaf-walker/actions?query=workflow%3A%22CI%22)

"Walk" CSAF data from a remote server, allowing one to work with the data.

In addition, this repository also has a tool for working with SBOM data. Most of the options explained are valid for
both SBOM and CSAF.

## From the command line

There's a command line tool, which can be used right away.

### Installation

Download a ready-to-run binary from the GitHub release page: <https://github.com/ctron/csaf-walker/releases>

You can also use `cargo binstall` to install such a binary:

```shell
cargo binstall csaf-cli
cargo binstall sbom-cli
```

Or compile it yourself, using plain `cargo install`:

```shell
cargo install csaf-cli
cargo install sbom-cli
```

### Usage

You can download all documents by providing a domain of the CSAF trusted provider:

```shell
mkdir out
csaf sync -3 -v -d out/ redhat.com
```

It is also possible to only download files, skipping the validation step (which can be done later using an already
downloaded copy):

```shell
mkdir out
csaf download -3 -v -d out/ redhat.com
```

> [!NOTE]
> In cases where data is signed with a GPG v3 signature, you can use the `-3` flag, which considers this still valid.
>
> An alternative is to use the `--policy-date` argument, and provide a manual policy date. Also
> see: <https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html>.

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

### Sending data

Instead of storing, it is also possible to send data to a remote instance (using the Vexination or Bombastic API).

```shell
csaf send -3 redhat.com http://localhost:8083
```

Of course, it is also possible to use the filesystem as a source:

```shell
csaf send -3 file:out/ http://localhost:8083
```

## As a library

Using the crate `csaf-walker`, this can also be used as a library:

```rust
use anyhow::Result;
use url::Url;
use csaf_walker::source::HttpSource;
use csaf_walker::walker::Walker;
use csaf_walker::retrieve::RetrievingVisitor;
use csaf_walker::validation::{ValidatedAdvisory, ValidationError, ValidationVisitor};
use walker_common::fetcher::Fetcher;

async fn walk() -> Result<()> {
    let fetcher = Fetcher::new(Default::default()).await?;
    let metadata = MetadataRetriever::new("redhat.com");
    let source = HttpSource::new(metadata, fetcher, Default::default());

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
