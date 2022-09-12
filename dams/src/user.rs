//! Models for the first pass of MongoDB integration.
//!
//! Includes structs for the various models found in the first round of Mongo
//! integration. This module will likely be split by model into sub-modules.

use crate::{
    config::opaque::OpaqueCipherSuite,
    crypto::{CryptoError, Encrypted, KeyId, Secret, StorageKey},
    DamsError,
};

use bson::Bson;
use opaque_ke::ServerRegistration;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr, vec::IntoIter};
use uuid::Uuid;

/// Unique ID for a user.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UserId(String);

impl UserId {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self, DamsError> {
        // Generate a UUID from bytes
        let mut id = [0_u8; 16];
        rng.try_fill(&mut id)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;
        let uuid = Uuid::from_bytes(id);

        // Store the UUID as a string to simplify database queries
        Ok(Self(uuid.to_string()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub(crate) fn len(&self) -> usize {
        self.as_bytes().len()
    }
}

impl IntoIterator for UserId {
    type Item = u8;
    type IntoIter = IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_bytes().into_iter()
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<UserId> for Bson {
    fn from(user_id: UserId) -> Self {
        Bson::String(user_id.0)
    }
}

/// Account name used as human-memorable identifier for a user during OPAQUE.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountName(String);

impl Display for AccountName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AccountName {
    type Err = DamsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl AccountName {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Wrapper around an [`Encrypted<Secret>`] and its [`KeyId`]
#[derive(Debug, Deserialize, Serialize)]
pub struct StoredSecret {
    secret: Encrypted<Secret>,
    key_id: KeyId,
}

impl StoredSecret {
    pub fn new(secret: Encrypted<Secret>, key_id: KeyId) -> Self {
        Self { secret, key_id }
    }
}

/// One user with a set of arbitrary secrets and a [`ServerRegistration`] to
/// authenticate with.
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub user_id: UserId,
    pub account_name: AccountName,
    pub storage_key: Option<Encrypted<StorageKey>>,
    pub secrets: Vec<StoredSecret>,
    pub server_registration: ServerRegistration<OpaqueCipherSuite>,
}

impl User {
    pub fn new(
        user_id: UserId,
        account_name: AccountName,
        server_registration: ServerRegistration<OpaqueCipherSuite>,
    ) -> Self {
        User {
            user_id,
            account_name,
            storage_key: None,
            secrets: Vec::new(),
            server_registration,
        }
    }

    pub fn into_parts(self) -> (ServerRegistration<OpaqueCipherSuite>, UserId) {
        (self.server_registration, self.user_id)
    }
}

/// Abstraction to wrap around [`UserId`] and [`AccountName`] as user
/// identifiers for log entries.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogIdentifier(String);

impl From<&UserId> for LogIdentifier {
    fn from(user_id: &UserId) -> Self {
        Self(user_id.clone().0)
    }
}

impl From<&AccountName> for LogIdentifier {
    fn from(account_name: &AccountName) -> Self {
        Self(account_name.clone().0)
    }
}
