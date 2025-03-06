//! Defines a `TokenFetcher` struct that will automatically refresh tokens
//! at some configured time prior to the token's expiration.

use crate::auth::{JwtClaims, Token};
use crate::credentials::Credentials;
use crate::{Result, get_token_with_client_and_body};

use arc_swap::ArcSwapOption;
use reqwest::Client;
use smpl_jwt::Jwt;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

/// A `TokenFetcher` stores a `Token` on first fetch and will continue returning
/// that token until it needs to be refreshed, as determined by the token's
/// `expires_in` field and the configured `refresh_buffer`.
///
/// Specifically on each token fetch request, it will check the current time
/// against the expected time the currently stored token will expire. If it
/// is within the `refresh_buffer` window, it will fetch a new token, store
/// that (along with the new expired time), and return the new token.
pub struct TokenFetcher {
    client: Client,
    jwt: Arc<Mutex<Jwt<JwtClaims>>>,
    credentials: Credentials,
    token_state: ArcSwapOption<TokenState>,
    refresh_buffer: Duration,
}

struct TokenState {
    /// The currently stored token
    token: Token,
    /// The lower bound of the time at which the token needs to be refreshed
    refresh_at: OffsetDateTime,
}

impl TokenFetcher {
    pub fn new(
        jwt: Jwt<JwtClaims>,
        credentials: Credentials,
        refresh_buffer: Duration,
    ) -> TokenFetcher {
        TokenFetcher::with_client(Client::new(), jwt, credentials, refresh_buffer)
    }

    pub fn with_client(
        client: Client,
        jwt: Jwt<JwtClaims>,
        credentials: Credentials,
        refresh_buffer: Duration,
    ) -> TokenFetcher {
        let token_state = ArcSwapOption::from(None);

        TokenFetcher {
            client,
            jwt: Arc::new(Mutex::new(jwt)),
            credentials,
            token_state,
            refresh_buffer,
        }
    }

    /// Returns a token if the token is still considered "valid" per the
    /// currently stored token's `expires_in` field and the configured
    /// `refresh_buffer`. If it is, return the stored token. If not,
    /// fetch a new token, store it, and return the new token.
    pub async fn fetch_token(&self) -> Result<Token> {
        let token_state = self.token_state.load();

        match &*token_state {
            // First time calling `fetch_token` since initialization, so fetch
            // a token.
            None => self.get_token().await,
            Some(token_state) => {
                let now = OffsetDateTime::now_utc();

                if now >= token_state.refresh_at {
                    // We have an existing token but it is time to refresh it
                    self.get_token().await
                } else {
                    // We have an existing, valid token, so return immediately
                    Ok(token_state.token.clone())
                }
            }
        }
    }

    /// Refresh the token
    async fn get_token(&self) -> Result<Token> {
        let now = OffsetDateTime::now_utc();
        let jwt_body = self.get_jwt_body(now)?;
        let token = get_token_with_client_and_body(&self.client, jwt_body, &self.credentials).await?;
        let expires_in = Duration::new(token.expires_in().into(), 0);

        assert!(
            expires_in >= self.refresh_buffer,
            "Received a token whose expires_in is less than the configured refresh buffer!"
        );

        let refresh_at = now + (expires_in - self.refresh_buffer);
        let token_state = TokenState {
            token: token.clone(),
            refresh_at,
        };

        self.token_state.swap(Some(Arc::new(token_state)));
        Ok(token)
    }

    fn get_jwt_body(&self, valid_from: OffsetDateTime) -> Result<String> {
        let mut jwt = self.jwt.lock().unwrap();
        // Refresh jwt claims
        jwt.body_mut().update(Some(valid_from.unix_timestamp()), None);
        let jwt_body = jwt.finalize()?;
        Ok(jwt_body)
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::{JwtClaims, Token};
    use crate::credentials::Credentials;
    use crate::fetcher::TokenFetcher;
    use crate::scopes::Scope;
    use mockito::{self, mock};
    use smpl_jwt::Jwt;
    use std::thread;
    use std::time::Duration as StdDuration;
    use time::Duration;

    fn get_mocks() -> (Jwt<JwtClaims>, Credentials) {
        let token_url = mockito::server_url();
        let iss = "some_iss";

        let mut credentials =
            Credentials::from_file("dummy_credentials_file_for_tests.json").unwrap();
        credentials.token_uri = token_url.clone();

        let claims = JwtClaims::new(
            String::from(iss),
            &Scope::DevStorageReadWrite,
            String::from(token_url.clone()),
            None,
            None,
        );

        let jwt = Jwt::new(claims, credentials.rsa_key().unwrap(), None);

        (jwt, credentials)
    }

    fn token_json(access_token: &str, token_type: &str, expires_in: u32) -> (Token, String) {
        let json = serde_json::json!({
            "access_token": access_token.to_string(),
            "token_type": token_type.to_string(),
            "expires_in": expires_in
        });

        let token = serde_json::from_value(json.clone()).unwrap();

        (token, json.to_string())
    }

    #[tokio::test]
    async fn basic_token_fetch() {
        let (jwt, credentials) = get_mocks();

        let refresh_buffer = Duration::new(0, 0);
        let fetcher = TokenFetcher::new(jwt, credentials, refresh_buffer);

        let (expected_token, json) = token_json("token", "Bearer", 1);

        let _mock = mock("POST", "/").with_status(200).with_body(json).create();

        let token = fetcher.fetch_token().await.unwrap();
        assert_eq!(expected_token, token);
    }

    #[tokio::test]
    async fn basic_token_refresh() {
        let (jwt, credentials) = get_mocks();

        let refresh_buffer = Duration::new(0, 0);
        let fetcher = TokenFetcher::new(jwt, credentials, refresh_buffer);

        let expires_in = 1;
        let (_expected_token, json) = token_json("token", "Bearer", expires_in);

        let mock = mock("POST", "/")
            .with_status(200)
            .with_body(json)
            .expect(2) // we expect to be hit twice due to refresh
            .create();

        // this should work
        fetcher.fetch_token().await.unwrap();

        // sleep for `expires_in`
        thread::sleep(StdDuration::from_secs(expires_in.into()));

        // this should refresh
        fetcher.fetch_token().await.unwrap();

        mock.assert();
    }

    #[tokio::test]
    async fn token_refresh_with_buffer() {
        let (jwt, credentials) = get_mocks();

        let refresh_buffer = 4;
        let fetcher = TokenFetcher::new(jwt, credentials, Duration::new(refresh_buffer, 0));

        let expires_in = 5;
        let (_expected_token, json) = token_json("token", "Bearer", expires_in);

        let mock = mock("POST", "/")
            .with_status(200)
            .with_body(json)
            .expect(2) // we expect to be hit twice due to refresh
            .create();

        // this should work
        fetcher.fetch_token().await.unwrap();

        // sleep for `expires_in`
        let sleep_for = expires_in - (refresh_buffer as u32);
        thread::sleep(StdDuration::from_secs(sleep_for.into()));

        // this should refresh
        fetcher.fetch_token().await.unwrap();

        mock.assert();
    }

    #[tokio::test]
    async fn doesnt_token_refresh_unnecessarily() {
        let (jwt, credentials) = get_mocks();

        let refresh_buffer = Duration::new(0, 0);
        let fetcher = TokenFetcher::new(jwt, credentials, refresh_buffer);

        let expires_in = 1;
        let (_expected_token, json) = token_json("token", "Bearer", expires_in);

        let mock = mock("POST", "/")
            .with_status(200)
            .with_body(json)
            .expect(1) // we expect to be hit only once
            .create();

        // this should work
        fetcher.fetch_token().await.unwrap();

        // fetch again, should not refresh
        fetcher.fetch_token().await.unwrap();

        mock.assert();
    }

    /// Ensure that `TokenFetcher` is `Send` and `Sync`
    #[test]
    fn is_send_and_sync() {
        let (jwt, credentials) = get_mocks();
        let refresh_buffer = Duration::new(0, 0);
        let fetcher = TokenFetcher::new(jwt, credentials, refresh_buffer);

        fn check(_: &(dyn Send + Sync)) {}

        check(&fetcher);
    }
}
