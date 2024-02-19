use crate::report::{DocumentKey, ReportResult};
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use url::Url;
use walker_common::report;

#[derive(Clone, Debug)]
pub struct ReportRenderOption {
    pub output: PathBuf,

    pub base_url: Option<Url>,
}

pub fn render_to_html<W: std::io::Write>(
    out: &mut W,
    report: &ReportResult,
    options: ReportRenderOption,
) -> anyhow::Result<()> {
    report::render(
        out,
        "CSAF Report",
        HtmlReport {
            result: report,
            base_url: &options.base_url,
        },
        &Default::default(),
    )?;

    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Title {
    Duplicates,
    Warnings,
    Errors,
}

impl Display for Title {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicates => f.write_str("Duplicates"),
            Self::Warnings => f.write_str("Warnings"),
            Self::Errors => f.write_str("Errors"),
        }
    }
}

struct HtmlReport<'r> {
    result: &'r ReportResult<'r>,
    base_url: &'r Option<Url>,
}

impl HtmlReport<'_> {
    fn render_duplicates(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let count = self.result.duplicates.duplicates.len();
        let data = |f: &mut Formatter<'_>| {
            for (k, v) in &self.result.duplicates.duplicates {
                let (_url, label) = self.link_document(k);
                writeln!(
                    f,
                    r#"
            <tr>
                <td><code>{label}<code></td>
                <td class="text-right">{v}</td>
            </tr>
            "#,
                    label = html_escape::encode_text(&label),
                )?;
            }
            Ok(())
        };

        if !self.result.duplicates.duplicates.is_empty() {
            let total: usize = self.result.duplicates.duplicates.values().sum();

            Self::render_table(
                f,
                count,
                Title::Duplicates,
                format!(
                    "{:?} duplicates URLs found, totalling {:?} redundant entries",
                    count, total
                )
                .as_str(),
                data,
            )?;
        }
        Ok(())
    }

    fn render_errors(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let count = self.result.errors.len();
        let data = |f: &mut Formatter<'_>| {
            for (k, v) in self.result.errors {
                let (url, label) = self.link_document(k);

                writeln!(
                    f,
                    r#"
            <tr>
                <td><a href="{url}" target="_blank" style="white-space: nowrap;">{label}</a></td>
                <td><code>{v}</code></td>
            </tr>
            "#,
                    url = html_escape::encode_quoted_attribute(&url),
                    label = html_escape::encode_text(&label),
                    v = html_escape::encode_text(&v),
                )?;
            }
            Ok(())
        };
        Self::render_table(
            f,
            count,
            Title::Errors,
            format!("{:?} error(s) detected", count).as_str(),
            data,
        )?;
        Ok(())
    }

    fn render_table<F>(
        f: &mut Formatter<'_>,
        count: usize,
        title: Title,
        sub_title: &str,
        data: F,
    ) -> std::fmt::Result
    where
        F: Fn(&mut Formatter<'_>) -> std::fmt::Result,
    {
        Self::title(f, title, count)?;
        writeln!(f, "<p>{sub_title}</p>")?;
        writeln!(
            f,
            r#"
    <table class="table">
        <thead>
            <tr>
                <th scope="col">File</th>
                <th scope="col">{title}</th>
            </tr>
        </thead>

        <tbody>
"#
        )?;
        data(f)?;
        writeln!(f, "</tbody></table>")?;

        Ok(())
    }

    fn render_warnings(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut count = 0;
        for warnings in self.result.warnings.values() {
            count += warnings.len();
        }

        let data = |f: &mut Formatter<'_>| {
            for (k, v) in self.result.warnings {
                let (url, label) = self.link_document(k);

                writeln!(
                    f,
                    r#"
            <tr>
                <td><a href="{url}" target="_blank" style="white-space: nowrap;">{label}</a></td>
                <td><ul>
"#,
                    url = html_escape::encode_quoted_attribute(&url),
                    label = html_escape::encode_text(&label),
                )?;

                for text in v {
                    writeln!(
                        f,
                        r#"
            <li>
                <code>{v}</code>
            </li>
            "#,
                        v = html_escape::encode_text(&text),
                    )?;
                }

                writeln!(
                    f,
                    r#"
                    </ul>
                </td>
            </tr>
"#
                )?;
            }

            Ok(())
        };
        Self::render_table(
            f,
            count,
            Title::Warnings,
            format!("{:?} warning(s) detected", count).as_str(),
            data,
        )?;
        Ok(())
    }

    fn gen_link(&self, key: &DocumentKey) -> Option<(String, String)> {
        let label = key.url.clone();

        // the full URL of the document
        let url = key.distribution_url.join(&key.url).ok()?;

        let url = match &self.base_url {
            Some(base_url) => base_url
                .make_relative(&url)
                .unwrap_or_else(|| url.to_string()),
            None => url.to_string(),
        };

        Some((url, label))
    }

    /// create a link towards a document, returning url and label
    fn link_document(&self, key: &DocumentKey) -> (String, String) {
        self.gen_link(key)
            .unwrap_or_else(|| (key.url.clone(), key.url.clone()))
    }

    fn title(f: &mut Formatter<'_>, title: Title, count: usize) -> std::fmt::Result {
        write!(f, "<h2>{title}")?;

        let (class, text) = if count > 0 {
            (
                match title {
                    Title::Warnings => "text-bg-warning",
                    _ => "text-bg-danger",
                },
                count.to_string(),
            )
        } else {
            ("text-bg-light", "None".to_string())
        };

        write!(
            f,
            r#" <span class="badge {class} rounded-pill">{text}</span>"#,
        )?;

        writeln!(f, "</h2>")?;

        Ok(())
    }

    fn render_total(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            r#"
<h2>Summary</h2>
<dl class="row">
    <dt class="col-sm-2">Total</dt>
    <dd class="col-sm-10">{total}</dd>
</dl>
"#,
            total = self.result.total
        )
    }
}

impl<'r> Display for HtmlReport<'r> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.render_total(f)?;
        self.render_duplicates(f)?;
        self.render_errors(f)?;
        self.render_warnings(f)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use reqwest::Url;

    #[test]
    fn test_link() {
        let details = ReportResult {
            total: 0,
            duplicates: &Default::default(),
            errors: &Default::default(),
            warnings: &Default::default(),
        };
        let _output = PathBuf::default();
        let base_url = Some(Url::parse("file:///foo/bar/").expect("example value must parse"));
        let report = HtmlReport {
            result: &details,
            base_url: &base_url,
        };

        let (url, _label) = report.link_document(&DocumentKey {
            distribution_url: Url::parse("file:///foo/bar/distribution/")
                .expect("example value must parse"),
            url: "2023/cve.json".to_string(),
        });

        assert_eq!(url, "distribution/2023/cve.json");
    }
}
