use super::ReportResult;
use std::fmt::{Display, Formatter};

pub fn render_to_html<W: std::io::Write>(out: &mut W, report: &ReportResult) -> anyhow::Result<()> {
    write!(
        out,
        r#"
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CSAF Report</title>
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
        report = HtmlReport(report)
    )?;
    Ok(())
}

struct HtmlReport<'r>(&'r ReportResult<'r>);

impl HtmlReport<'_> {
    fn render_duplicates(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Self::title(f, "Duplicates", self.0.duplicates.duplicates.len())?;

        if !self.0.duplicates.duplicates.is_empty() {
            let num = self.0.duplicates.duplicates.len();
            let total: usize = self.0.duplicates.duplicates.values().sum();
            writeln!(
                f,
                "<p>{num} duplicates URLs found, totalling {total} redundant entries</p>",
            )?;

            writeln!(f, "<p>The following URLs have duplicate entries:</p>")?;

            writeln!(
                f,
                r#"
    <table class="table">
        <thead>
            <tr>
                <th scope="col">File</th>
                <th scope="col"># Duplicates</th>
            </tr>
        </thead>
        
        <tbody>
"#
            )?;

            for (k, v) in &self.0.duplicates.duplicates {
                writeln!(
                    f,
                    r#"
            <tr>
                <td><code>{k}<code></td>
                <td class="text-right">{v}</td>
            </tr>
            "#,
                    k = html_escape::encode_text(&k),
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

    fn render_errors(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Self::title(f, "Errors", self.0.errors.len())?;

        if !self.0.errors.is_empty() {
            let num = self.0.errors.len();
            let s = match num {
                1 => "",
                _ => "s",
            };
            writeln!(f, "<p>{num} error{s} detected</p>")?;

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
                writeln!(
                    f,
                    r#"
            <tr>
                <td><a href="{k}">{k}</a></td>
                <td><code>{v}</code></td>
            </tr>
            "#,
                    k = html_escape::encode_quoted_attribute(&k),
                    v = html_escape::encode_text(&v),
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
        writeln!(
            f,
            r#"
<h1>CSAF Report</h1>
"#
        )?;

        self.render_duplicates(f)?;
        self.render_errors(f)?;

        Ok(())
    }
}
