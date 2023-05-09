# CSAF Walker

"Walk" CSAF data from a remote server, allowing one to work with the data.

## From the command line

```shell
csaf download -3 -v -o out/ https://access.redhat.com/security/data/csaf/v2/provider-metadata.json
```

## In Rust

```rust
async fn main() {
    Walker::new(discover.source, client.clone())
        .walk(RetrievingVisitor::new(
            client.clone(),
            ValidationVisitor::new(
                client,
                move |advisory: Result<ValidatedAdvisory, ValidationError>| async move {
                    log::info!("Found advisory: {advisory:?}");
                },
            )
        ))
        .await?;
}
```
