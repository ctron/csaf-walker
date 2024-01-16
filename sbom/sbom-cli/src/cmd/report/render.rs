use super::ReportResult;
use crate::cmd::report::RenderOptions;
use reqwest::Url;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use walker_common::report;

pub fn render_to_html<W: std::io::Write>(
    out: &mut W,
    report: &ReportResult,
    render: &RenderOptions,
) -> anyhow::Result<()> {
    report::render(
        out,
        "SBOM Report",
        HtmlReport(report, render),
        &Default::default(),
    )?;

    Ok(())
}

struct HtmlReport<'r>(&'r ReportResult<'r>, &'r RenderOptions);

impl HtmlReport<'_> {
    fn render_errors(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Self::title(f, "Errors", self.0.errors.len())?;

        if !self.0.errors.is_empty() {
            writeln!(
                f,
                r#"
    <table class="table">
        <thead>
            <tr>
                <th scope="col">File</th>
                <th scope="col">Error</th>
            </tr>
        </thead>
        
        <tbody>
"#
            )?;

            for (k, v) in self.0.errors {
                let k: Cow<str> = match (&self.1.base_url, Url::parse(k)) {
                    (Some(base_url), Ok(url)) => match base_url.make_relative(&url) {
                        Some(url) => Cow::Owned(url),
                        None => Cow::Borrowed(k),
                    },
                    _ => Cow::Borrowed(k),
                };

                writeln!(
                    f,
                    r#"
            <tr>
                <td><a href="{k}" target="_blank" style="white-space: nowrap;">{k}</a></td>
                <td><code>{v}</code></td>
            </tr>
            "#,
                    k = html_escape::encode_quoted_attribute(&k),
                    v = html_escape::encode_text(&v.to_string()),
                )?;
            }

            writeln!(
                f,
                r#"
        <tbody>
    </table>
"#
            )?;
        }

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
            total = self.0.total
        )
    }

    fn title(f: &mut Formatter<'_>, title: &str, count: usize) -> std::fmt::Result {
        write!(f, "<h2>{title}")?;

        let (class, text) = if count > 0 {
            ("text-bg-danger", count.to_string())
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
}

impl<'r> Display for HtmlReport<'r> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.render_total(f)?;
        self.render_errors(f)?;

        Ok(())
    }
}
