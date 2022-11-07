//! Database models for secrets

use crate::crypto::{Encrypted, KeyId, PlaceholderEncryptedSigningKeyPair, Secret, SigningKeyPair};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Holds user's stored secrets of all types
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct StoredSecrets {
    pub arbitrary_secrets: Vec<StoredEncryptedSecret>,
    pub signing_keys: Vec<StoredEncryptedSigningKeyPair>,
    pub server_created_signing_keys: Vec<StoredSigningKeyPair>,
}

/// Wrapper around an [`Encrypted<Secret>`] and its [`KeyId`]
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredEncryptedSecret {
    pub secret: Encrypted<Secret>,
    pub key_id: KeyId,
    pub retrieved: bool,
}

impl StoredEncryptedSecret {
    pub fn new(secret: Encrypted<Secret>, key_id: KeyId) -> Self {
        Self {
            secret,
            key_id,
            retrieved: false,
        }
    }
}

/// Wrapper around an [`Encrypted<SigningKeyPair>`] and its [`KeyId`].
///
/// This is used to hold signing key pairs encrypted by the client before being
/// sent by the server.
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredEncryptedSigningKeyPair {
    pub signing_key: Encrypted<SigningKeyPair>,
    pub key_id: KeyId,
    pub retrieved: bool,
}

impl StoredEncryptedSigningKeyPair {
    pub fn new(secret: Encrypted<SigningKeyPair>, key_id: KeyId) -> Self {
        Self {
            signing_key: secret,
            key_id,
            retrieved: false,
        }
    }
}

/// Wrapper around an [`SigningKeyPair`] and its [`KeyId`]
///
/// This is used to hold signing key pairs sent by the client in the clear and
/// encrypted by the server.
#[derive(Debug, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct StoredSigningKeyPair {
    pub signing_key: PlaceholderEncryptedSigningKeyPair,
    #[zeroize(skip)]
    pub key_id: KeyId,
    #[zeroize(skip)]
    pub retrieved: bool,
}

impl StoredSigningKeyPair {
    pub fn new(secret: SigningKeyPair, key_id: KeyId) -> Self {
        Self {
            signing_key: secret.into(),
            key_id,
            retrieved: false,
        }
    }
}
