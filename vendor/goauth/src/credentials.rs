use crate::{GoErr, Result};
use smpl_jwt::RSAKey;
use std::fs::File;
use std::io::prelude::*;

use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials {
    #[serde(rename = "type")]
    t: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    // pub(crate) to this can be overriden in tests
    pub(crate) token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}

impl Credentials {
    pub fn from_file(fp: &str) -> Result<Self> {
        let mut f = File::open(fp)?;
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer)?;
        Ok(serde_json::from_slice(buffer.as_slice())?)
    }

    pub fn rsa_key(&self) -> Result<RSAKey> {
        Ok(RSAKey::from_str(&self.private_key)?)
    }

    pub fn iss(&self) -> String {
        self.client_email.clone()
    }

    pub fn project(&self) -> String {
        self.project_id.clone()
    }

    pub fn token_uri(&self) -> String {
        self.token_uri.clone()
    }
}

impl FromStr for Credentials {
    type Err = GoErr;
    fn from_str(s: &str) -> Result<Self, GoErr> {
        Ok(serde_json::from_str(s)?)
    }
}
