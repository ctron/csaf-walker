use url::Url;

/// Get a URL from something
///
/// ## Relative URLs
///
/// A entity can provide a relative URL. This is an optional operation, and is not implemented by default.
///
/// Implementors of this feature should have a clear definition what the meaning of the base is. For example:
/// the advisory's base is the distribution URL.
///
/// The combination of the provided actual base and relative URL must result in the same value as the actual URL.
pub trait Urlify {
    /// The URL
    fn url(&self) -> &Url;

    fn relative_base_and_url(&self) -> Option<(&Url, String)> {
        None
    }

    fn relative_url(&self) -> Option<String> {
        self.relative_base_and_url().map(|(_, url)| url)
    }

    fn relative_base(&self) -> Option<&Url> {
        self.relative_base_and_url().map(|(url, _)| url)
    }

    fn possibly_relative_url(&self) -> String {
        self.relative_url()
            .unwrap_or_else(|| self.url().to_string())
    }
}

impl<T, E> Urlify for Result<T, E>
where
    T: Urlify,
    E: Urlify,
{
    fn url(&self) -> &Url {
        match self {
            Ok(something) => something.url(),
            Err(something) => something.url(),
        }
    }
}
