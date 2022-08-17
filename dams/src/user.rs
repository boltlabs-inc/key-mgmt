//! Models for the first pass of MongoDB integration.
//!
//! Includes structs for the various models found in the first round of Mongo
//! integration. This module will likely be split by model into sub-modules.

use std::fmt::{Display, Write};

use crate::{config::opaque::OpaqueCipherSuite, crypto::Secret};

use opaque_ke::ServerRegistration;
use serde::{Deserialize, Serialize};

/// Unique ID for a user. Assumption: this will be derived from an ID generated
/// by the Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserId(Box<[u8; 16]>);

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:?}", self.0))
    }
}

impl UserId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// One user with a set of arbitrary secrets and a [`ServerRegistration`] to
/// authenticate with.
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    user_id: UserId,
    secrets: Vec<Secret>,
    server_registration: ServerRegistration<OpaqueCipherSuite>,
}

impl User {
    pub fn new(
        user_id: UserId,
        server_registration: ServerRegistration<OpaqueCipherSuite>,
    ) -> Self {
        User {
            user_id,
            secrets: Vec::new(),
            server_registration,
        }
    }

    pub fn into_server_registration(self) -> ServerRegistration<OpaqueCipherSuite> {
        self.server_registration
    }
}
