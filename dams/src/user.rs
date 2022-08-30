//! Models for the first pass of MongoDB integration.
//!
//! Includes structs for the various models found in the first round of Mongo
//! integration. This module will likely be split by model into sub-modules.

use crate::{config::opaque::OpaqueCipherSuite, crypto::Secret};

use opaque_ke::ServerRegistration;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, fmt::Display, str::FromStr};

/// Unique ID for a user.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserId(Box<[u8; 16]>);

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self.0))
    }
}

impl UserId {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut id = [0_u8; 16];
        // TODO: this can panic
        rng.fill_bytes(&mut id);
        Self(Box::new(id))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
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
    type Err = Infallible;

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
