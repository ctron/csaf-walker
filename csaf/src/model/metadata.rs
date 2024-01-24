use chrono::{DateTime, Utc};
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Distribution {
    pub directory_url: Option<Url>,
    pub rolie: Option<Rolie>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Rolie {
    pub categories: Vec<Url>,
    pub feeds: Vec<Feed>,
    pub services: Vec<Url>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Feed {
    pub summary: String,
    pub tip_label: Tlp_label,
    pub url: Url,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum Tlp_label {
    UNLABELED,
    WHITE,
    GREEN,
    AMBER,
    RED,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Key {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub url: Url,
}

impl<'a> From<&'a Key> for walker_common::validate::source::Key<'a> {
    fn from(value: &'a Key) -> Self {
        walker_common::validate::source::Key {
            fingerprint: value.fingerprint.as_deref(),
            url: &value.url,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Publisher {
    pub category: String,
    pub contact_details: String,
    pub issuing_authority: String,
    pub name: String,
    pub namespace: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct ProviderMetadata {
    pub canonical_url: Url,

    #[serde(default)]
    pub distributions: Vec<Distribution>,

    pub last_updated: DateTime<Utc>,

    #[serde(rename = "list_on_CSAF_aggregators")]
    #[serde(default)]
    pub list_on_csaf_aggregators: bool,

    pub metadata_version: String,

    #[serde(rename = "mirror_on_CSAF_aggregators")]
    #[serde(default)]
    pub mirror_on_csaf_aggregators: bool,

    #[serde(default)]
    pub public_openpgp_keys: Vec<Key>,

    pub publisher: Publisher,

    /// Contains the role of the issuing party according to section 7 in the CSAF standard.
    #[serde(default = "default_role")]
    pub role: Role,
}

const fn default_role() -> Role {
    Role::Provider
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
pub enum Role {
    #[serde(rename = "csaf_publisher")]
    Publisher,
    #[serde(rename = "csaf_provider")]
    Provider,
    #[serde(rename = "csaf_trusted_provider")]
    TrustedProvider,
}
