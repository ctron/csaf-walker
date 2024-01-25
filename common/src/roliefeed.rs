use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize)]
pub struct RolieFeed {
    #[serde(rename = "feed")]
    pub feed: Feed,
}

#[derive(Serialize, Deserialize)]
pub struct Feed {
    #[serde(rename = "entry")]
    pub entry: Vec<Entry>,

    #[serde(rename = "link")]
    link: Vec<Link>,

    #[serde(rename = "id")]
    id: String,

    #[serde(rename = "title")]
    title: String,

    #[serde(rename = "category")]
    category: Vec<Category>,

    #[serde(rename = "updated", with = "time::serde::rfc3339")]
    updated: OffsetDateTime,
}

#[derive(Serialize, Deserialize)]
pub struct Category {
    #[serde(rename = "scheme")]
    scheme: String,

    #[serde(rename = "term")]
    term: String,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "link")]
    pub link: Vec<Link>,

    #[serde(rename = "format")]
    format: Format,

    #[serde(rename = "id")]
    id: String,

    #[serde(rename = "published", with = "time::serde::rfc3339")]
    published: OffsetDateTime,

    #[serde(rename = "title")]
    title: String,

    #[serde(rename = "updated", with = "time::serde::rfc3339")]
    pub updated: OffsetDateTime,

    #[serde(rename = "content")]
    content: Content,
}

#[derive(Serialize, Deserialize)]
pub struct Content {
    #[serde(rename = "src")]
    src: String,

    #[serde(rename = "type")]
    content_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct Format {
    #[serde(rename = "schema")]
    schema: String,

    #[serde(rename = "version")]
    version: String,
}

#[derive(Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "rel")]
    rel: String,

    #[serde(rename = "href")]
    pub href: String,
}

// #[derive(Serialize, Deserialize)]
// pub enum Rel {
//     #[serde(rename = "hash")]
//     Hash,
//
//     #[serde(rename = "self")]
//     RelSelf,
//
//     #[serde(rename = "signature")]
//     Signature,
//
//     #[serde(rename = "service")]
//     Service,
// }
