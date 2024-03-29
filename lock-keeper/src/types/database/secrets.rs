//! This module specifies our [`StoredSecret`] type. Which is a general representation
//! of a secret to be stored in our database.

use crate::{
    crypto::{DataBlob, Encrypted, KeyId, Secret, SigningKeyPair},
    types::database::secrets::secret_types::SERVER_ENCRYPTED_BLOB,
    LockKeeperError,
};
use serde::{Deserialize, Serialize};

use super::account::AccountId;

/// Generic representation of a secret that is stored in a database.
/// Databased implementors must be able to store and return [`StoredSecret`]s. So
/// we make all fields in this struct public.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StoredSecret {
    pub key_id: KeyId,
    pub account_id: AccountId,
    pub secret_type: String,
    pub bytes: Vec<u8>,
    /// Whether or not this secret has been retrieved.
    pub retrieved: bool,
}

impl StoredSecret {
    pub fn new(
        key_id: KeyId,
        account_id: AccountId,
        secret_type: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, LockKeeperError> {
        let secret = secret.into();

        Ok(Self {
            key_id,
            account_id,
            secret_type: secret_type.into(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_arbitrary_secret(
        key_id: KeyId,
        account_id: AccountId,
        secret: Encrypted<Secret>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            account_id,
            secret_type: secret_types::ARBITRARY_SECRET.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_signing_key_pair(
        key_id: KeyId,
        account_id: AccountId,
        secret: Encrypted<SigningKeyPair>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            account_id,
            secret_type: secret_types::SIGNING_KEY_PAIR.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_remote_signing_key_pair(
        key_id: KeyId,
        secret: Encrypted<SigningKeyPair>,
        account_id: AccountId,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            account_id,
            secret_type: secret_types::REMOTE_SIGNING_KEY.to_string(),
            bytes: serde_json::to_vec(&secret)?,
            retrieved: false,
        })
    }

    pub fn from_data_blob(
        key_id: KeyId,
        account_id: AccountId,
        blob: Encrypted<DataBlob>,
    ) -> Result<Self, LockKeeperError> {
        Ok(Self {
            key_id,
            account_id,
            secret_type: SERVER_ENCRYPTED_BLOB.to_string(),
            bytes: serde_json::to_vec(&blob)?,
            retrieved: false,
        })
    }
}

pub mod secret_types {
    pub const ARBITRARY_SECRET: &str = "arbitrary_secret";
    pub const SIGNING_KEY_PAIR: &str = "signing_key_pair";
    pub const REMOTE_SIGNING_KEY: &str = "remote_signing_key";
    pub const SERVER_ENCRYPTED_BLOB: &str = "server_encrypted_blob";
}

impl TryFrom<StoredSecret> for Encrypted<SigningKeyPair> {
    type Error = LockKeeperError;

    fn try_from(secret: StoredSecret) -> Result<Self, Self::Error> {
        if secret.secret_type == secret_types::SIGNING_KEY_PAIR
            || secret.secret_type == secret_types::REMOTE_SIGNING_KEY
        {
            Ok(serde_json::from_slice(&secret.bytes)?)
        } else {
            Err(LockKeeperError::InvalidSecretType)
        }
    }
}
