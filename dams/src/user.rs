//! Models for the first pass of MongoDB integration.
//!
//! Includes structs for the various models found in the first round of Mongo
//! integration. This module will likely be split by model into sub-modules.

use crate::{
    config::opaque::OpaqueCipherSuite,
    crypto::{CryptoError, Secret},
    DamsError,
};

use opaque_ke::ServerRegistration;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{array::IntoIter, fmt::Display, str::FromStr};
use uuid::Uuid;

/// Unique ID for a user.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UserId(Uuid);

impl UserId {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self, DamsError> {
        let mut id = [0_u8; 16];
        rng.try_fill(&mut id)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;
        let uuid = Uuid::from_bytes(id);
        Ok(Self(uuid))
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
        self.0.into_bytes().into_iter()
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self.0))
    }
}

/// Account name used as human-memorable identifier for a user during OPAQUE.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// One user with a set of arbitrary secrets and a [`ServerRegistration`] to
/// authenticate with.
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    user_id: UserId,
    account_name: AccountName,
    secrets: Vec<Secret>,
    server_registration: ServerRegistration<OpaqueCipherSuite>,
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
            secrets: Vec::new(),
            server_registration,
        }
    }

    pub fn into_parts(self) -> (ServerRegistration<OpaqueCipherSuite>, UserId) {
        (self.server_registration, self.user_id)
    }
}
