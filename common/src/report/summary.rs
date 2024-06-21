use std::fmt::{Display, Formatter};

pub struct Summary<K: Display, V: Display>(pub Vec<(K, V)>);

impl<K: Display, V: Display> Display for Summary<K, V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, r#"<h2>Summary</h2>"#)?;
        writeln!(f, r#"<dl class="row">"#)?;
        for (k, v) in &self.0 {
            writeln!(
                f,
                r#"
    <dt class="col-sm-2">{k}</dt>
    <dd class="col-sm-10">{v}</dd>
"#
            )?;
        }
        writeln!(f, r#"</dl>"#)?;

        Ok(())
    }
}
