//! Cryptography, protocols, and other shared types and context used by multiple
//! entities in the Lock Keeper digital asset management system.
//!
//! ⚠️ __Usage__: This crate should _not_ be used directly by developers outside
//! of Bolt Labs. It is designed as a dependency for other crates in the
//! ecosystem, including `dams-key-server` and `dams-client`.
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

use serde::{Deserialize, Serialize};
use std::fmt;
use tonic::Status;

pub mod blockchain;
pub mod config;
pub mod crypto;
pub mod defaults;
pub mod keys;
pub mod opaque_storage;
pub mod timeout;
pub mod transaction;
pub mod user;

#[allow(clippy::all)]
pub mod dams_rpc {
    tonic::include_proto!("dams_rpc");
}

/// Logs used to verify that an operation completed in the integration tests.
#[derive(Debug)]
pub enum TestLogs {
    /// Server successfully serving at address described by parameter.
    ServerSpawned(String),
}

impl fmt::Display for TestLogs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TestLogs::ServerSpawned(addr) => format!("serving on: {:?}", addr),
            }
        )
    }
}

pub fn deserialize_from_bytes<'a, T: Deserialize<'a>>(message: &'a [u8]) -> Result<T, Status> {
    let deserialized: T = bincode::deserialize(message)
        .map_err(|_| Status::aborted("Unable to deserialize message"))?;
    Ok(deserialized)
}

pub fn serialize_to_bytes<T: Serialize>(message: &T) -> Result<Vec<u8>, Status> {
    let serialized: Vec<u8> =
        bincode::serialize(message).map_err(|_| Status::aborted("Unable to serialize message"))?;
    Ok(serialized)
}
