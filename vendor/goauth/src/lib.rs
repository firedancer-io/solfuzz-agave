#[macro_use]
extern crate serde_derive;

#[cfg(test)]
#[macro_use]
extern crate doc_comment;

pub mod auth;
pub mod credentials;
pub mod fetcher;
pub mod scopes;

use auth::{JwtClaims, Token};
use credentials::Credentials;

use reqwest::Client;
use smpl_jwt::Jwt;
use std::str::FromStr;

use tokio::runtime::Runtime;

const DEFAULT_URL: &str = "https://www.googleapis.com/oauth2/v4/token";

fn form_body(body: &str) -> Vec<(&str, &str)> {
    vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", body),
    ]
}

simpl::err!(GoErr,
{
    Io@std::io::Error;
    Jwt@smpl_jwt::JwtErr;
    Json@serde_json::Error;
    Reqwest@reqwest::Error;
    Token@auth::TokenErr;
});

/// Get Token which can be used to authenticate further request
/// ### Example
///
/// ```
/// extern crate smpl_jwt;
/// extern crate goauth;
/// #[macro_use]
/// extern crate log;
///
/// use goauth::auth::JwtClaims;
/// use goauth::scopes::Scope;
/// use goauth::get_token_legacy;
/// use smpl_jwt::{RSAKey, Jwt};
///
/// fn main() {
///   let token_url = "https://www.googleapis.com/oauth2/v4/token";
///   let iss = "some_iss"; // https://developers.google.com/identity/protocols/OAuth2ServiceAccount
///   let private_key_file = "random_rsa_for_testing";
///
///   let claims = JwtClaims::new(String::from(iss),
///                              &Scope::DevStorageReadWrite,
///                              String::from(token_url),
///                              None, None);
///   let key = match RSAKey::from_pem(private_key_file) {
///     Ok(x) => x,
///     Err(e) => panic!("{}", e)
///   };
///   let jwt = Jwt::new(claims, key, None);
///   match get_token_legacy(&jwt, None) {
///     Ok(x) => debug!("{}", x),
///     Err(e) => debug!("{}", e)
///   };
/// }
///
/// ```
pub fn get_token_legacy(jwt: &Jwt<JwtClaims>, url: Option<&str>) -> Result<Token> {
    let client = reqwest::blocking::Client::new();
    let final_jwt = jwt.finalize()?;
    let request_body = form_body(&final_jwt);
    let response = client
        .post(url.unwrap_or(DEFAULT_URL))
        .form(&request_body)
        .send()?;

    Token::from_str(&response.text()?)
}

pub fn get_token_as_string_legacy(jwt: &Jwt<JwtClaims>, url: Option<&str>) -> Result<String> {
    Ok(serde_json::to_string(&get_token_legacy(jwt, url)?)?)
}

pub fn get_token_as_string(jwt: &Jwt<JwtClaims>, credentials: &Credentials) -> Result<String> {
    Ok(serde_json::to_string(&get_token_blocking(
        jwt,
        credentials,
    )?)?)
}

/// Get Token which can be used to authenticate further request
/// ### Example
///
/// ```
/// extern crate smpl_jwt;
/// extern crate goauth;
/// #[macro_use]
/// extern crate log;
///
/// use goauth::auth::JwtClaims;
/// use goauth::scopes::Scope;
/// use goauth::credentials::Credentials;
/// use goauth::get_token_blocking;
/// use smpl_jwt::Jwt;
///
/// fn main() {
///
///   let credentials = Credentials::from_file("dummy_credentials_file_for_tests.json").unwrap();
///
///   let claims = JwtClaims::new(credentials.iss(),
///                              &Scope::DevStorageReadWrite,
///                              credentials.token_uri(),
///                              None, None);
///
///   let jwt = Jwt::new(claims, credentials.rsa_key().unwrap(), None);
///   match get_token_blocking(&jwt, &credentials) {
///     Ok(x) => debug!("{}", x),
///     Err(e) => debug!("{}", e)
///   };
/// }
///
/// ```
pub fn get_token_blocking(jwt: &Jwt<JwtClaims>, credentials: &Credentials) -> Result<Token> {
    let rt = Runtime::new()?;
    rt.block_on(get_token(jwt, credentials))
}

/// Async get Token which can be used to authenticate further request
/// ### Example
///
/// ```
/// extern crate smpl_jwt;
/// extern crate goauth;
/// #[macro_use]
/// extern crate log;
/// extern crate futures;
///
/// use goauth::auth::JwtClaims;
/// use goauth::scopes::Scope;
/// use goauth::credentials::Credentials;
/// use goauth::GoErr;
/// use goauth::get_token;
/// use smpl_jwt::Jwt;
/// use futures::future::Future;
///
///
/// fn main() -> Result<(), GoErr> {
///
///   let credentials = Credentials::from_file("dummy_credentials_file_for_tests.json").unwrap();
///
///   let claims = JwtClaims::new(credentials.iss(),
///                              &Scope::DevStorageReadWrite,
///                              credentials.token_uri(),
///                              None, None);
///
///   let jwt = Jwt::new(claims, credentials.rsa_key().unwrap(), None);
///   async {
///     match get_token(&jwt, &credentials).await {
///         Ok(token) => println!("{}", token),
///         Err(_) => panic!("An error occurred, somewhere in there, try debugging with `get_token_with_creds`")
///     }
///   };
///   Ok(())
/// }
///
/// ```
pub async fn get_token(jwt: &Jwt<JwtClaims>, credentials: &Credentials) -> Result<Token> {
    let client = Client::new();

    get_token_with_client(&client, jwt, credentials).await
}

pub async fn get_token_with_client(
    client: &Client,
    jwt: &Jwt<JwtClaims>,
    credentials: &Credentials,
) -> Result<Token> {
    let jwt_body = jwt.finalize()?;

    get_token_with_client_and_body(client, jwt_body, credentials).await
}

pub(crate) async fn get_token_with_client_and_body(
    client: &Client,
    jwt_body: String,
    credentials: &Credentials,
) -> Result<Token> {
    let request_body = form_body(&jwt_body);

    let response = client
        .post(&credentials.token_uri())
        .form(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        let token = response.json::<Token>().await?;
        Ok(token)
    } else {
        let token_err = response.json::<auth::TokenErr>().await?;
        Err(GoErr::from(token_err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    doctest!("../README.md");

    #[test]
    fn test_jwt_encode() {
        use auth::JwtClaims;
        use scopes::Scope;
        use smpl_jwt::{Jwt, RSAKey};

        let token_url = "https://www.googleapis.com/oauth2/v4/token";
        let iss = "some_iss"; // https://developers.google.com/identity/protocols/OAuth2ServiceAccount
        let private_key_file = "random_rsa_for_testing";

        let claims = JwtClaims::new(
            String::from(iss),
            &Scope::DevStorageReadWrite,
            String::from(token_url),
            Some(1482317385),
            Some(3600),
        );
        let key = match RSAKey::from_pem(private_key_file) {
            Ok(x) => x,
            Err(e) => panic!("{}", e),
        };
        let jwt = Jwt::new(claims, key, None);
        assert_eq!(jwt.finalize().unwrap(), "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzb21lX2lzcyIsInNjb3BlIjoiaHR0cHM6Ly93d3cuZ29vZ2xlYXBpcy5jb20vYXV0aC9kZXZzdG9yYWdlLnJlYWRfd3JpdGUiLCJhdWQiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9vYXV0aDIvdjQvdG9rZW4iLCJleHAiOjE0ODIzMjA5ODUsImlhdCI6MTQ4MjMxNzM4NX0=.BldQozpzNYnLnYWBbqwAWY1j2hPDD3oVY9EOG0eRJN77sC4ZInEyGJT5eXLD39C726TdrEVCHmvhKBJFmaFL2BXNto69_v8lz-3oGnFL5FkUr4RRpukd_6tj7-RZzx15LIzdTqzKfAUlqWoZUdze8Fcd1NJ6w1g49CCghvN_eryvecALpjnHoBkKlIXnSm_udiSf26cYWvCikmW5g8nUqAduFsIYfR-4LMwyUfYH1hNC64SRsfLH9bL4-tyeaoUCv5MXTIhxrJbrhQy3TEOSc5didDrMoYNUu_qjJvxBQbq1Um1W1SpyvSd4eVJn18xZcOmCnoE73RDZcxT5hDpaRQ==");
    }

    #[test]
    fn get_token_test() {
        //  This test will always pass, output is logged via debug macro
        use auth::JwtClaims;
        use scopes::Scope;
        use smpl_jwt::{Jwt, RSAKey};

        let token_url = "https://www.googleapis.com/oauth2/v4/token";
        let iss = "some_iss"; // https://developers.google.com/identity/protocols/OAuth2ServiceAccount
        let private_key_file = "random_rsa_for_testing";

        let claims = JwtClaims::new(
            String::from(iss),
            &Scope::DevStorageReadWrite,
            String::from(token_url),
            None,
            None,
        );
        let key = match RSAKey::from_pem(private_key_file) {
            Ok(x) => x,
            Err(e) => panic!("{}", e),
        };
        let jwt = Jwt::new(claims, key, None);
        match get_token_legacy(&jwt, None) {
            Ok(x) => println!("{}", x),
            Err(e) => println!("{}", e),
        };
    }
}
