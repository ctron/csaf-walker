use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Key {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub url: Url,
}

impl From<Url> for Key {
    fn from(value: Url) -> Self {
        let fingerprint = value.fragment().map(ToString::to_string);
        Self {
            url: value,
            fingerprint,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct SourceMetadata {
    pub url: Url,
    pub keys: Vec<Key>,
}

impl<'a> From<&'a Key> for walker_common::validate::source::Key<'a> {
    fn from(value: &'a Key) -> Self {
        walker_common::validate::source::Key {
            fingerprint: value.fingerprint.as_deref(),
            url: &value.url,
        }
    }
}
