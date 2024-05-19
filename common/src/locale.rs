use std::fmt::{Display, Formatter};

/// Format a number in a locale specific way
pub struct Formatted(pub usize);

impl Display for Formatted {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
