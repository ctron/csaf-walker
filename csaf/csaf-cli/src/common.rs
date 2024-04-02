use crate::cmd::DiscoverArguments;
use anyhow::bail;
use csaf_walker::{
    discover::DiscoveredVisitor,
    metadata::MetadataRetriever,
    retrieve::RetrievingVisitor,
    source::{DispatchSource, FileOptions, FileSource, HttpOptions, HttpSource},
    validation::{ValidatedVisitor, ValidationVisitor},
    visitors::filter::{FilterConfig, FilteringVisitor},
    walker::Walker,
};
use fluent_uri::Uri;
use reqwest::Url;
use std::future::Future;
use std::path::PathBuf;
use std::time::SystemTime;
use walker_common::{
    cli::{client::ClientArguments, runner::RunnerArguments, validation::ValidationArguments},
    progress::Progress,
    validate::ValidationOptions,
};

pub async fn walk_standard<V>(
    progress: Progress,
    client: ClientArguments,
    runner: RunnerArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
    validation: ValidationArguments,
    visitor: V,
) -> anyhow::Result<()>
where
    V: ValidatedVisitor,
    V::Error: Send + Sync + 'static,
{
    let options: ValidationOptions = validation.into();

    walk_visitor(
        progress,
        client,
        discover,
        filter,
        runner,
        move |source| async move {
            Ok(RetrievingVisitor::new(
                source.clone(),
                ValidationVisitor::new(visitor).with_options(options),
            ))
        },
    )
    .await
}

pub struct DiscoverConfig {
    /// The source to locate the provider metadata.
    ///
    /// This can be either a full path to a provider-metadata.json, or a base domain used by the
    /// CSAF metadata discovery process.
    pub source: String,

    /// Only report documents which have changed since the provided date. If a document has no
    /// change information, or this field is [`None`], it will always be reported.
    pub since: Option<SystemTime>,
}

impl DiscoverConfig {
    pub fn with_since(mut self, since: impl Into<Option<SystemTime>>) -> Self {
        self.since = since.into();
        self
    }
}

impl From<DiscoverArguments> for DiscoverConfig {
    fn from(value: DiscoverArguments) -> Self {
        Self {
            since: None,
            source: value.source,
        }
    }
}

impl From<&str> for DiscoverConfig {
    fn from(value: &str) -> Self {
        Self {
            since: None,
            source: value.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
enum SourceDescriptor {
    File(PathBuf),
    Url(Url),
    Lookup(String),
}

impl SourceDescriptor {
    pub fn from(source: &str) -> anyhow::Result<Self> {
        match Uri::parse(source) {
            Ok(uri) => match uri.scheme().map(|s| s.as_str()) {
                Some("https") => Ok(SourceDescriptor::Url(Url::parse(source)?)),
                Some("file") => Ok(SourceDescriptor::File(PathBuf::from(uri.path().as_str()))),
                Some(other) => bail!("URLs with scheme '{other}' are not supported"),
                None => Ok(SourceDescriptor::Lookup(source.to_string())),
            },
            Err(err) => {
                log::debug!("Failed to handle source as URL: {err}");
                Ok(SourceDescriptor::Lookup(source.to_string()))
            }
        }
    }

    pub async fn into_source(
        self,
        discover: DiscoverConfig,
        client: ClientArguments,
    ) -> anyhow::Result<DispatchSource> {
        match self {
            Self::File(path) => {
                Ok(FileSource::new(path, FileOptions::new().since(discover.since))?.into())
            }
            Self::Url(url) => Ok(HttpSource::new(
                url,
                client.new_fetcher().await?,
                HttpOptions::new().since(discover.since),
            )
            .into()),
            Self::Lookup(source) => {
                let fetcher = client.new_fetcher().await?;
                Ok(HttpSource::new(
                    MetadataRetriever::new(source),
                    fetcher,
                    HttpOptions::new().since(discover.since),
                )
                .into())
            }
        }
    }
}

pub async fn new_source(
    discover: impl Into<DiscoverConfig>,
    client: ClientArguments,
) -> anyhow::Result<DispatchSource> {
    let discover = discover.into();

    let descriptor = SourceDescriptor::from(&discover.source)?;
    descriptor.into_source(discover, client).await
}

/// Create a [`FilteringVisitor`] from a [`FilterConfig`].
pub fn filter<V>(filter: impl Into<FilterConfig>, visitor: V) -> FilteringVisitor<V>
where
    V: DiscoveredVisitor,
{
    FilteringVisitor {
        visitor,
        config: filter.into(),
    }
}

pub async fn walk_visitor<F, Fut, V>(
    progress: Progress,
    client: ClientArguments,
    discover: impl Into<DiscoverConfig>,
    filter: impl Into<FilterConfig>,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let source = new_source(discover, client).await?;

    walk_source(progress, source, filter, runner, f).await
}

pub async fn walk_source<F, Fut, V>(
    progress: Progress,
    source: DispatchSource,
    filter_config: impl Into<FilterConfig>,
    runner: RunnerArguments,
    f: F,
) -> anyhow::Result<()>
where
    F: FnOnce(DispatchSource) -> Fut,
    Fut: Future<Output = anyhow::Result<V>>,
    V: DiscoveredVisitor,
    V::Error: Send + Sync + 'static,
{
    let visitor = f(source.clone()).await?;
    let walker = Walker::new(source).with_progress(progress);

    match runner.workers {
        1 => {
            walker.walk(filter(filter_config, visitor)).await?;
        }
        n => {
            walker
                .walk_parallel(n, filter(filter_config, visitor))
                .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;

    #[tokio::test]
    async fn test_file_relative() {
        let source = SourceDescriptor::from("file:../../foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "../../foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute() {
        let source = SourceDescriptor::from("file:/foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute_double() {
        let source = SourceDescriptor::from("file:///foo/bar");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/foo/bar")
        );
    }

    #[tokio::test]
    async fn test_file_absolute_windows() {
        let source = SourceDescriptor::from("file:///c:/DATA/example");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::File(path)) if path.to_string_lossy() == "/c:/DATA/example")
        );
    }

    #[tokio::test]
    async fn test_base() {
        let source = SourceDescriptor::from("base.domain");
        println!("Result: {source:?}");
        assert!(matches!(source, Ok(SourceDescriptor::Lookup(base)) if base == "base.domain"));
    }

    #[tokio::test]
    async fn test_https() {
        let source = SourceDescriptor::from("https://base.domain");
        println!("Result: {source:?}");
        assert!(
            matches!(source, Ok(SourceDescriptor::Url(url)) if url.as_str() == "https://base.domain/")
        );
    }

    #[tokio::test]
    async fn test_gopher() {
        let source = SourceDescriptor::from("gopher://base.domain");
        println!("Result: {source:?}");
        assert!(source.is_err());
    }
}
