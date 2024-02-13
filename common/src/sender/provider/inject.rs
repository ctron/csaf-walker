use super::{Credentials, TokenProvider};
use crate::sender::Error;
use async_trait::async_trait;
use tracing::instrument;

/// Allows injecting tokens.
#[async_trait]
pub trait TokenInjector: Sized + Send + Sync {
    async fn inject_token(self, token_provider: &dyn TokenProvider) -> Result<Self, Error>;
}

/// Injects tokens into a request by setting the authorization header to a "bearer" token.
#[async_trait]
impl TokenInjector for reqwest::RequestBuilder {
    #[instrument(level = "debug", skip(token_provider), err)]
    async fn inject_token(self, token_provider: &dyn TokenProvider) -> Result<Self, Error> {
        let credentials_result = token_provider.provide_access_token().await?;
        if let Some(credentials) = credentials_result {
            let request_builder = match credentials {
                Credentials::Bearer(token) => self.bearer_auth(token),
                Credentials::Basic(username, password) => self.basic_auth(username, password),
            };
            Ok(request_builder)
        } else {
            Ok(self)
        }
    }
}
