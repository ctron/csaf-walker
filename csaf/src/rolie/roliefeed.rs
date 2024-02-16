use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize)]
pub struct RolieFeed {
    pub feed: Feed,
}

#[derive(Serialize, Deserialize)]
pub struct Feed {
    pub entry: Vec<Entry>,

    pub link: Vec<Link>,

    pub id: String,

    pub title: String,

    pub category: Vec<Category>,

    #[serde(with = "time::serde::rfc3339")]
    updated: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct Category {
    pub scheme: String,

    pub term: String,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
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

#[derive(Serialize, Deserialize)]
pub struct Content {
    pub src: String,

    #[serde(rename = "type")]
    pub content_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct Format {
    pub schema: String,

    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct Link {
    pub rel: String,

    pub href: String,
}
