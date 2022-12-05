//! Database models for secrets

use crate::{
    crypto::{Encrypted, KeyId, Secret, SigningKeyPair},
    LockKeeperError,
};
use serde::{Deserialize, Serialize};

/// Generic representation of a secret that is stored in a database.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredSecret {
    pub key_id: KeyId,
    pub secret_type: String,
    pub bytes: Vec<u8>,
    pub retrieved: bool,
}

impl StoredSecret {
    pub fn new(
        key_id: KeyId,
        secret_type: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, LockKeeperError> {
        let secret = secret.into();

        Ok(Self {
            key_id,
            secret_type: secret_type.into(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_arbitrary_secret(
        key_id: KeyId,
        secret: Encrypted<Secret>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            secret_type: secret_types::ARBITRARY_SECRET.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_signing_key_pair(
        key_id: KeyId,
        secret: Encrypted<SigningKeyPair>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            secret_type: secret_types::SIGNING_KEY_PAIR.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_remote_signing_key_pair(
        key_id: KeyId,
        secret: Encrypted<SigningKeyPair>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            secret_type: secret_types::REMOTE_SIGNING_KEY.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }
}

pub mod secret_types {
    pub const ARBITRARY_SECRET: &str = "arbitrary_secret";
    pub const SIGNING_KEY_PAIR: &str = "signing_key_pair";
    pub const REMOTE_SIGNING_KEY: &str = "remote_signing_key";
}

impl TryFrom<StoredSecret> for Encrypted<SigningKeyPair> {
    type Error = LockKeeperError;

    fn try_from(secret: StoredSecret) -> Result<Self, Self::Error> {
        if secret.secret_type == secret_types::SIGNING_KEY_PAIR {
            Ok(serde_json::from_slice(&secret.bytes)?)
        } else {
            Err(LockKeeperError::InvalidSecretType)
        }
    }
}
