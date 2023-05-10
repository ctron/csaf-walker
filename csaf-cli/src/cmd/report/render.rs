use super::ReportResult;
use comrak::plugins::syntect::SyntectAdapter;
use comrak::{markdown_to_html_with_plugins, ComrakOptions, ComrakPlugins};
use std::fmt::Write;

pub fn render_report<W: Write>(mut w: W, report: &ReportResult) -> anyhow::Result<()> {
    writeln!(w, "# CSAF Report")?;
    writeln!(w)?;

    writeln!(w, "## Duplicates")?;
    writeln!(w)?;

    if report.duplicates.duplicates.is_empty() {
        writeln!(w, "No duplicates detected")?;
        writeln!(w,)?;
    } else {
        let num = report.duplicates.duplicates.len();
        let total: usize = report.duplicates.duplicates.values().sum();
        writeln!(
            w,
            "{num} duplicates URLs found, totalling {total} redundant entries",
        )?;
        writeln!(w,)?;

        writeln!(w, "The following URLs have duplicate entries:")?;
        writeln!(w)?;

        writeln!(w, "| File | # Duplicates | ")?;
        writeln!(w, "| ---- | -----------: | ")?;

        for (k, v) in &report.duplicates.duplicates {
            writeln!(w, "| `{k}` | {v} | ")?;
        }
        writeln!(w,)?;
    }

    writeln!(w, "## Errors")?;

    if report.errors.is_empty() {
        writeln!(w, "No error detected")?;
        writeln!(w,)?;
    } else {
        let num = report.errors.len();
        let s = match num {
            1 => "",
            _ => "s",
        };
        writeln!(w, "{num} error{s} detected")?;
        writeln!(w,)?;

        writeln!(w, "| File | Error | ")?;
        writeln!(w, "| ---- | -----------: | ")?;

        for (k, v) in report.errors {
            writeln!(w, "| `{k}` | {v} | ")?;
        }

        writeln!(w,)?;
    }

    Ok(())
}

pub fn render_to_html<W: std::io::Write>(markdown: &str, mut out: W) -> anyhow::Result<()> {
    let adapter = SyntectAdapter::new("Solarized (light)");
    let options = ComrakOptions::default();
    let mut plugins = ComrakPlugins::default();

    plugins.render.codefence_syntax_highlighter = Some(&adapter);

    let formatted = markdown_to_html_with_plugins(&markdown, &options, &plugins);

    writeln!(out, "{}", formatted)?;

    Ok(())
}
