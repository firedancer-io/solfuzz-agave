use std::error::Error;
use std::str::FromStr;

use crate::scopes::Scope;
use crate::GoErr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
}

impl JwtClaims {
    pub fn update(&mut self, valid_from: Option<i64>, expires_after: Option<i64>) {
        let iat = match valid_from {
            Some(x) => x,
            None => time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        let expires_after = match expires_after {
            Some(x) => x,
            None => self.exp - self.iat,
        };
        self.iat = iat;
        self.exp = iat + expires_after
    }

    pub fn refresh(&self, valid_from: Option<i64>, expires_after: Option<i64>) -> JwtClaims {
        let iat = match valid_from {
            Some(x) => x,
            None => time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        let expires_after = match expires_after {
            Some(x) => x,
            None => self.exp - self.iat,
        };
        let mut claims = self.clone();
        claims.iat = iat;
        claims.exp = iat + expires_after;
        claims

    }

    pub fn new(
        service_acc_id: String,
        scope: &Scope,
        aud_url: String,
        valid_from: Option<i64>,
        expires_after: Option<i64>,
    ) -> Self {
        let iat = match valid_from {
            Some(x) => x,
            None => time::OffsetDateTime::now_utc().unix_timestamp(),
        };
        let exp = match expires_after {
            Some(x) => iat + x,
            None => iat + 3600,
        };
        JwtClaims {
            iss: service_acc_id,
            scope: scope.url(),
            aud: aud_url,
            exp,
            iat,
        }
    }
}

impl std::fmt::Display for JwtClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", &serde_json::to_string_pretty(&self).unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenErr {
    error: String,
    error_description: String,
}

impl std::fmt::Display for TokenErr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "TokenErr: {}", self.error_description)
    }
}

impl Error for TokenErr {
    fn description(&self) -> &str {
        &self.error_description
    }

    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct Token {
    access_token: String,
    token_type: String,
    expires_in: u32,
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Token: (type: {}, expires_in: {})",
            self.token_type, self.expires_in
        )
    }
}

impl Token {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn expires_in(&self) -> u32 {
        self.expires_in
    }
}

impl FromStr for Token {
    type Err = GoErr;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match serde_json::from_str(s) {
            Ok(x) => Ok(x),
            Err(e) => Err(e.into()),
        }
    }
}
