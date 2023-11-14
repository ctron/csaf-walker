use url::Url;

/// Get a URL from something
pub trait Urlify {
    fn url(&self) -> &Url;
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
