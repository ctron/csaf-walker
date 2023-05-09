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
    } else {
        writeln!(
            w,
            "{} duplicates URLs found, totalling {} redundant entries",
            report.duplicates.duplicates.len(),
            report
                .duplicates
                .duplicates
                .iter()
                .map(|(_, v)| *v)
                .sum::<usize>(),
        )?;
        writeln!(w,)?;

        writeln!(w, "The following URLs have duplicate entries:")?;
        writeln!(w)?;
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
