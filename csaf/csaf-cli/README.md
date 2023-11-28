# csaf

A tool to work with CSAF data from the command line.

This tool can also be used as a library: <https://crates.io/crates/csaf-walker>

## Usage

```
Commands:
  parse     Parse advisories
  download  Like sync, but doesn't validate
  scan      Scan advisories
  discover  Discover advisories, just lists the URLs
  sync      Sync only what changed, and alidate
  report    Analyze (and report) the state of the data
  send      Sync only what changed, and don't validate
  help      Print this message or the help of the given subcommand(s)
```

### Parse

Parse a CSAF document, or fail trying.

### Discover

Discover a list of URLs, pointing to CSAF document on a remove server. This will perform the lookup of the metadata,
and emit a URL per line with the discovered documents.

Example:

```
cargo run -- discover https://redhat.com
```

### Download

Discover and download CSAF documents.

### Sync

Discover, download, and validate CSAF documents.

This works similar to the `download` command, but will also perform some integrity validation (like digest, signatures).
It will however not verify the content of documents.

### Report

Discover, validate, and verify CSAF documents.

This discovers and temporarily downloads CSAF documents, performing validation and verification of the content.

**NOTE:** This commands works best of already downloaded data (a combination of running `download` and then `report`).

### Send

Discover, download, validate, and send CSAF documents to a remote endpoint.

Instead of storing content locally, this forwards content to a remote endpoint.

## Common options

### Sources

The CSAF tooling can discover and retrieve CSAF documents from two services: HTTP and file systems. Additionally,
when downloading CSAF documents, the tool will write content into the file system, so that it can later be used
as a file system source.

The idea behind that is that it is possible to split up the process of downloading and processing documents.

If a source string can be parsed as a URL, it is processes as an HTTP/HTTPS source. Otherwise, it will be used
as a file system location.

**NOTE:** The structure of the filesystem storage is currently not considered an API. It is only guaranteed that
whatever is store can be read back by tools of the same version. Also, is it currently not a format which can be
hosted directly as a new CSAF repository.

### Signature verification

When signatures get verified it may be possible that signature algorithms are considered "too old". If that's the case,
and you still want to allow them, it is possible to provide the "policy date", which sets the defaults for what is
still allowed (also see: <https://docs.rs/sequoia-policy-config/latest/sequoia_policy_config/>).

Specifically, when encountering GPG v3 signatures, one can also use the `-3` switch.
