//! Database models for secrets

use crate::crypto::{Encrypted, KeyId, Secret};

use serde::{Deserialize, Serialize};

/// Wrapper around an [`Encrypted<Secret>`] and its [`KeyId`]
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredSecret {
    pub secret: Encrypted<Secret>,
    pub key_id: KeyId,
    pub retrieved: bool,
}

impl StoredSecret {
    pub fn new(secret: Encrypted<Secret>, key_id: KeyId) -> Self {
        Self {
            secret,
            key_id,
            retrieved: false,
        }
    }
}
