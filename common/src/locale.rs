use lazy_static::lazy_static;
use num_format::{
    utils::{DecimalStr, InfinityStr, MinusSignStr, NanStr, PlusSignStr, SeparatorStr},
    Format, Grouping, SystemLocale,
};

/// A dispatch for locales. Either the system locale, or a custom (default) one.
#[allow(clippy::large_enum_variant)]
pub enum Locale {
    System(SystemLocale),
    Custom(num_format::Locale),
}

impl Locale {
    /// Create a new locale, either using the system locale, or using the provided default as
    /// a fallback.
    pub fn new(default: num_format::Locale) -> Self {
        #[cfg(any(unix, windows))]
        return match SystemLocale::new() {
            Ok(locale) => Self::System(locale),
            Err(_) => Self::Custom(default),
        };
        #[cfg(not(any(unix, windows)))]
        Self::Custom(default)
    }
}

macro_rules! dispatch {
    ($v: expr, $f:ident) => {
        match $v {
            Self::System(l) => Format::$f(l),
            Self::Custom(l) => Format::$f(l),
        }
    };
}

impl Format for Locale {
    fn decimal(&self) -> DecimalStr<'_> {
        dispatch!(self, decimal)
    }

    fn grouping(&self) -> Grouping {
        dispatch!(self, grouping)
    }

    fn infinity(&self) -> InfinityStr<'_> {
        dispatch!(self, infinity)
    }

    fn minus_sign(&self) -> MinusSignStr<'_> {
        dispatch!(self, minus_sign)
    }

    fn nan(&self) -> NanStr<'_> {
        dispatch!(self, nan)
    }

    fn plus_sign(&self) -> PlusSignStr<'_> {
        dispatch!(self, plus_sign)
    }

    fn separator(&self) -> SeparatorStr<'_> {
        dispatch!(self, separator)
    }
}

lazy_static! {
    pub static ref LOCALE: Locale = Locale::new(num_format::Locale::en);
}
