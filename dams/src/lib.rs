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

use std::fmt;

pub mod blockchain;
pub mod channel;
pub mod config;
pub mod crypto;
pub mod defaults;
pub mod keys;
pub mod opaque_storage;
pub mod timeout;
pub mod transaction;
pub mod types;
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

/// Generates `TryFrom` implementations to and from the `Message` type for a
/// given list of types.
#[macro_export]
macro_rules! impl_message_conversion {
    ($($message_type:ty),+) => {
        $(
            impl TryFrom<$crate::types::Message> for $message_type {
                type Error = tonic::Status;

                fn try_from(value: $crate::types::Message) -> Result<Self, Self::Error> {
                    bincode::deserialize(&value.content)
                        .map_err(|e| tonic::Status::internal(e.to_string()))
                }
            }

            impl TryFrom<$message_type> for $crate::types::Message {
                type Error = tonic::Status;

                fn try_from(value: $message_type) -> Result<Self, Self::Error> {
                    let content = bincode::serialize(&value)
                        .map_err(|e| tonic::Status::internal(e.to_string()))?;

                    Ok($crate::types::Message { content })
                }
            }
        )+
    };
}
