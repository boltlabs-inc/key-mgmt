//! Models for the first pass of MongoDB integration.
//!
//! Includes structs for the various models found in the first round of Mongo
//! integration. This module will likely be split by model into sub-modules.

use crate::config::opaque::OpaqueCipherSuite;

use bytes::BytesMut;
use opaque_ke::ServerRegistration;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, str::FromStr};

/// Unique ID for a user. Assumption: this will be derived from an ID generated
/// by the Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserId(String);

impl ToString for UserId {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl FromStr for UserId {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserId(s.to_string()))
    }
}

impl UserId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Wrapper around [`BytesMut`] to represent one arbitrary secret.
#[derive(Debug, Deserialize, Serialize)]
pub struct Secret {
    material: BytesMut,
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
