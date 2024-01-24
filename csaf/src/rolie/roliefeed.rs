use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct RolieFeed {
    pub feed: Feed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Feed {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry: Vec<Entry>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub link: Vec<Link>,

    pub id: String,

    pub title: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category: Vec<Category>,

    #[serde(with = "time::serde::rfc3339")]
    pub updated: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Category {
    pub scheme: String,

    pub term: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub link: Vec<Link>,

    pub format: Format,

    pub id: String,

    #[serde(with = "time::serde::rfc3339")]
    pub published: OffsetDateTime,

    pub title: String,

    #[serde(with = "time::serde::rfc3339")]
    pub updated: OffsetDateTime,

    pub content: Content,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Content {
    pub src: String,

    #[serde(rename = "type")]
    pub content_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Format {
    pub schema: String,

    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Link {
    pub rel: String,

    pub href: String,
}
