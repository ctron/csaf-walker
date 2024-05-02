use super::{Credentials, TokenProvider};
use crate::sender::Error;
use std::future::Future;
use tracing::instrument;

/// Allows injecting tokens.
pub trait TokenInjector: Sized + Send + Sync {
    fn inject_token(
        self,
        token_provider: &dyn TokenProvider,
    ) -> impl Future<Output = Result<Self, Error>>;
}

/// Injects tokens into a request by setting the authorization header to a "bearer" token.
impl TokenInjector for reqwest::RequestBuilder {
    // Workaround until https://github.com/tokio-rs/tracing/issues/2876 is fixed
    #[allow(clippy::blocks_in_conditions)]
    #[instrument(level = "debug", skip(token_provider), err)]
    async fn inject_token(self, token_provider: &dyn TokenProvider) -> Result<Self, Error> {
        if let Some(credentials) = token_provider.provide_access_token().await? {
            Ok(match credentials {
                Credentials::Bearer(token) => self.bearer_auth(token),
                Credentials::Basic(username, password) => self.basic_auth(username, password),
            })
        } else {
            Ok(self)
        }
    }
}
