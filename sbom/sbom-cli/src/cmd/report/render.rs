use super::ReportResult;
use crate::cmd::report::RenderOptions;
use reqwest::Url;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;

pub fn render_to_html<W: std::io::Write>(
    out: &mut W,
    report: &ReportResult,
    render: &RenderOptions,
) -> anyhow::Result<()> {
    write!(
        out,
        r#"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SBOM Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous">
  </head>
  <body>
    <div class="container">
    {report}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+jjXkk+Q2h455rYXK/7HAuoJl+0I4" crossorigin="anonymous"></script>
  </body>
</html>

"#,
        report = HtmlReport(report, render)
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
        let date = humantime::Timestamp::from(SystemTime::now());

        writeln!(
            f,
            r#"
<h1>SBOM Report <span class="badge bg-secondary">{date}</span></h1>
"#,
        )?;

        self.render_total(f)?;
        self.render_errors(f)?;

        Ok(())
    }
}
