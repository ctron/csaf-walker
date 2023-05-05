use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Distribution {
    pub directory_url: Url,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Key {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub url: Url,
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

    pub last_updated: String,

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

    pub role: String,
}
