mod roliefeed;

pub use roliefeed::*;

use crate::source::HttpSourceError;
use time::OffsetDateTime;
use url::{ParseError, Url};
use walker_common::fetcher::Json;
use walker_common::{fetcher, fetcher::Fetcher};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Fetch error: {0}")]
    Fetcher(#[from] fetcher::Error),
    #[error("URL error: {0}")]
    Url(#[from] ParseError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<Error> for HttpSourceError {
    fn from(value: Error) -> Self {
        match value {
            Error::Fetcher(err) => Self::Fetcher(err),
            Error::Url(err) => Self::Url(err),
            Error::Json(err) => Self::Json(err),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct SourceFile {
    /// The relative or absolute file name
    pub file: String,

    /// The relative or absolute file name to the hash
    pub digest: Option<String>,

    /// The relative or absolute file name to the signature
    pub signature: Option<String>,

    /// The timestamp of the last change
    #[serde(with = "time::serde::iso8601")]
    pub timestamp: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct RolieSource {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<SourceFile>,
}

impl RolieSource {
    pub async fn retrieve(fetcher: &Fetcher, base_url: Url) -> Result<Self, Error> {
        let mut files = vec![];
        let Json(result) = fetcher.fetch::<Json<RolieFeed>>(base_url).await?;
        for entry in result.feed.entry {
            files.push(find_file(entry));
        }

        log::debug!("found {:?} files", files.len());

        Ok(Self { files })
    }
}

fn find_file(entry: Entry) -> SourceFile {
    let mut file = None;
    let mut signature = None;
    let mut digest = None;

    for link in entry.link {
        match &*link.rel {
            "self" => file = Some(link.href),
            "signature" => signature = Some(link.href),
            "hash" => digest = Some(link.href),
            _ => continue,
        }
    }

    SourceFile {
        file: file.unwrap_or(entry.content.src),
        timestamp: entry.updated,
        signature,
        digest,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn find_by_link() {
        let result = find_file(Entry {
            link: vec![
                Link {
                    rel: "self".to_string(),
                    href: "https://example.com/foo/bar/1.json".to_string(),
                },
                Link {
                    rel: "hash".to_string(),
                    href: "https://example.com/foo/bar/1.json.sha512".to_string(),
                },
                Link {
                    rel: "signature".to_string(),
                    href: "https://example.com/foo/bar/1.json.asc".to_string(),
                },
            ],
            format: Format {
                schema: "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
                    .to_string(),
                version: "2.0".to_string(),
            },
            id: "1".to_string(),
            published: datetime!(2025-01-01 00:00:00 UTC ),
            title: "Example entry".to_string(),
            updated: datetime!(2025-01-02 00:00:00 UTC ),
            content: Content {
                src: "https://example.com/foo/bar/1.json".to_string(),
                content_type: "application/json".to_string(),
            },
        });

        assert_eq!(
            result,
            SourceFile {
                file: "https://example.com/foo/bar/1.json".to_string(),
                digest: Some("https://example.com/foo/bar/1.json.sha512".to_string()),
                signature: Some("https://example.com/foo/bar/1.json.asc".to_string()),
                timestamp: datetime!(2025-01-02 00:00:00 UTC ),
            }
        );
    }
}
