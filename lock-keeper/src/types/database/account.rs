//! Database models for users and user-related fields

use crate::{
    config::opaque::OpaqueCipherSuite,
    crypto::{CryptoError, Encrypted, StorageKey},
    LockKeeperError,
};

use opaque_ke::ServerRegistration;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    array::{IntoIter, TryFromSliceError},
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

use super::HexBytes;

/// One user with a set of arbitrary secrets and a [`ServerRegistration`] to
/// authenticate with.
#[derive(Deserialize, Serialize)]
pub struct Account {
    pub account_id: AccountId,
    pub user_id: UserId,
    pub account_name: AccountName,
    pub storage_key: Option<Encrypted<StorageKey>>,
    pub server_registration: ServerRegistration<OpaqueCipherSuite>,
}

impl Account {
    pub fn id(&self) -> AccountId {
        self.account_id
    }
}

/// Manual implement Debug to avoid printing storage key or server_registration.
impl Debug for Account {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("user_id", &self.user_id)
            .field("account_name", &self.account_name)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct AccountId(pub i64);

impl From<i64> for AccountId {
    fn from(n: i64) -> Self {
        Self(n)
    }
}

impl From<AccountId> for i64 {
    fn from(account_id: AccountId) -> Self {
        account_id.0
    }
}

/// Unique ID for a user.
/// Wrapped in a `Box` to avoid stack overflows during heavy traffic.
#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
#[serde(try_from = "HexBytes", into = "HexBytes")]
pub struct UserId(Box<[u8; 16]>);

impl AsRef<[u8; 16]> for UserId {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}
impl TryFrom<&[u8]> for UserId {
    type Error = TryFromSliceError;

    fn try_from(id: &[u8]) -> Result<Self, Self::Error> {
        Ok(UserId(Box::new(<[u8; 16]>::try_from(id)?)))
    }
}

impl UserId {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self, LockKeeperError> {
        // Generate random bytes
        let mut id = [0_u8; 16];
        rng.try_fill(&mut id)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;

        Ok(Self(Box::new(id)))
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
    type IntoIter = IntoIter<u8, 16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Debug for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(*self.0);
        f.debug_tuple("UserId").field(&hex).finish()
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(*self.0);
        write!(f, "{hex}")
    }
}

impl From<UserId> for HexBytes {
    fn from(key_id: UserId) -> Self {
        (*key_id.0).into()
    }
}

impl TryFrom<HexBytes> for UserId {
    type Error = LockKeeperError;

    fn try_from(bytes: HexBytes) -> Result<Self, Self::Error> {
        Ok(UserId(Box::new(bytes.try_into()?)))
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

impl From<AccountName> for String {
    fn from(account_name: AccountName) -> Self {
        account_name.0
    }
}

impl AsRef<str> for AccountName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for AccountName {
    type Err = LockKeeperError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(AccountName(s.to_string()))
    }
}

impl From<&str> for AccountName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AccountName {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
