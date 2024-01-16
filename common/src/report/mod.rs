//! Common functionality for creating the reports

use std::fmt::Display;
use std::io::Write;
use time::macros::format_description;

const BOOTSTRAP_VERSION: &str = "5.2.3";
const BOOTSTRAP_CSS_SRI: &str =
    "sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65";
const BOOTSTRAP_JS_SRI: &str =
    "sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4";

#[derive(Clone, Debug, Default)]
pub struct ReportOptions {
    pub bootstrap: Bootstrap,
}

#[derive(Clone, Default, Debug)]
pub enum Bootstrap {
    /// Use a default version served from a CDN
    #[default]
    Default,
    /// Use a custom version
    Custom {
        /// The location to Bootstrap.
        ///
        /// The is considered the base URL, unless `js_location` is present as well. In which case it's considered a full URL.
        location: String,
        /// The specific location of the bootstrap JS file.
        js_location: Option<String>,
        /// An optional SRI value for the CSS resource
        css_integrity: Option<String>,
        /// An optional SRI value for the JS resource
        js_integrity: Option<String>,
    },
}

impl Bootstrap {
    pub fn css_location(&self) -> String {
        match self {
            Self::Default => format!("https://cdn.jsdelivr.net/npm/bootstrap@{BOOTSTRAP_VERSION}/dist/css/bootstrap.min.css"),
            Self::Custom {location, js_location, ..} => match js_location {
                Some(_) => location.clone(),
                None => format!("{location}/css/bootstrap.min.css" ),
            },
        }
    }

    pub fn css_integrity(&self) -> Option<String> {
        match self {
            Self::Default => Some(BOOTSTRAP_CSS_SRI.into()),
            Self::Custom { css_integrity, .. } => css_integrity.clone(),
        }
    }

    pub fn js_location(&self) -> String {
        match self {
            Self::Default => format!("https://cdn.jsdelivr.net/npm/bootstrap@{BOOTSTRAP_VERSION}/dist/js/bootstrap.bundle.min.js"),
            Self::Custom {location, js_location, ..} => {
                match js_location {
                    Some(js_location) => js_location.clone(),
                    None => format!("{location}/js/bootstrap.bundle.min.js")
                }
            }
        }
    }

    pub fn js_integrity(&self) -> Option<String> {
        match self {
            Self::Default => Some(BOOTSTRAP_JS_SRI.into()),
            Self::Custom { js_integrity, .. } => js_integrity.clone(),
        }
    }
}

pub fn render(
    mut write: impl Write,
    title: impl Display,
    report: impl Display,
    options: &ReportOptions,
) -> anyhow::Result<()> {
    writeln!(
        write,
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <link href="{css}" rel="stylesheet" {css_integrity} crossorigin="anonymous">
  </head>
  <body>
    <div class="container">
      <h1>
        {title} <span class="badge bg-secondary">{date}</span>
      </h1>
      {report}
    </div>
    <script src="{js}" {js_integrity} crossorigin="anonymous"></script>
  </body>
</html>
"#,
        date = time::OffsetDateTime::now_local()
            .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
            .format(&format_description!(
                "[year]-[month padding:zero]-[day padding:zero] [hour repr:24]:[minute padding:zero]:[second padding:zero] [offset_hour sign:mandatory]:[offset_minute]"
            ))
            .unwrap_or_else(|_| "Unknown".to_string()),
        css = html_escape::encode_quoted_attribute(&options.bootstrap.css_location()),
        js = html_escape::encode_quoted_attribute(&options.bootstrap.js_location()),
        css_integrity = options
            .bootstrap
            .css_integrity()
            .map(|sri| format!(
                r#"integrity="{sri}""#,
                sri = html_escape::encode_quoted_attribute(&sri)
            ))
            .unwrap_or_default(),
        js_integrity = options
            .bootstrap
            .css_integrity()
            .map(|sri| format!(
                r#"integrity="{sri}""#,
                sri = html_escape::encode_quoted_attribute(&sri)
            ))
            .unwrap_or_default(),
        title = html_escape::encode_text(&title.to_string()),
    )?;

    Ok(())
}
