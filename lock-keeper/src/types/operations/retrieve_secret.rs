use crate::{
    crypto::{Encrypted, KeyId, RemoteStorageKey, Secret, SigningKeyPair},
    types::database::{
        account::UserId,
        secrets::{secret_types, StoredSecret},
    },
    LockKeeperError,
};

use serde::{Deserialize, Serialize};

/// Options for the asset owner's intended use of a secret
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RetrieveContext {
    Null,
    LocalOnly,
}

/// Generic representation of a secret that is retrieved by a client.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetrievedSecret {
    pub key_id: KeyId,
    pub secret_type: String,
    pub bytes: Vec<u8>,
}

impl RetrievedSecret {
    pub fn try_from_stored_secret(
        stored_secret: StoredSecret,
        user_id: UserId,
        remote_storage_key: RemoteStorageKey,
    ) -> Result<Self, LockKeeperError> {
        let key_id = stored_secret.key_id.clone();
        let secret_type = stored_secret.secret_type.clone();
        match secret_type.as_str() {
            secret_types::ARBITRARY_SECRET | secret_types::SIGNING_KEY_PAIR => Ok(Self {
                key_id,
                secret_type,
                bytes: stored_secret.bytes,
            }),
            secret_types::REMOTE_SIGNING_KEY => {
                let encrypted_key: Encrypted<SigningKeyPair> = stored_secret.try_into()?;
                let key = encrypted_key.decrypt_signing_key_by_server(
                    &remote_storage_key,
                    user_id,
                    key_id.clone(),
                )?;
                Ok(Self {
                    key_id,
                    secret_type,
                    bytes: key.try_into()?,
                })
            }
            &_ => Err(LockKeeperError::InvalidSecretType),
        }
    }
}

impl TryFrom<RetrievedSecret> for Encrypted<Secret> {
    type Error = LockKeeperError;

    fn try_from(secret: RetrievedSecret) -> Result<Self, Self::Error> {
        if secret.secret_type == secret_types::ARBITRARY_SECRET {
            Ok(serde_json::from_slice(&secret.bytes)?)
        } else {
            Err(LockKeeperError::InvalidSecretType)
        }
    }
}

impl TryFrom<RetrievedSecret> for SigningKeyPair {
    type Error = LockKeeperError;

    fn try_from(secret: RetrievedSecret) -> Result<Self, Self::Error> {
        if secret.secret_type == secret_types::REMOTE_SIGNING_KEY {
            Ok(SigningKeyPair::try_from(secret.bytes)?)
        } else {
            Err(LockKeeperError::InvalidSecretType)
        }
    }
}

pub mod client {
    use crate::crypto::KeyId;
    use serde::{Deserialize, Serialize};

    use super::RetrieveContext;

    #[derive(Debug, Deserialize, Serialize)]
    /// pass user ID and key ID to server
    pub struct Request {
        pub key_id: KeyId,
        pub context: RetrieveContext,
        pub secret_type: Option<String>,
    }
}

pub mod server {
    use super::RetrievedSecret;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    /// return requested key and key ID
    pub struct Response {
        pub secret: RetrievedSecret,
    }
}
