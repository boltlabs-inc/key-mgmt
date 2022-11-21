//! Cryptography, protocols, and other shared types and context used by multiple
//! entities in the Lock Keeper digital asset management system.
//!
//! ⚠️ __Usage__: This crate should _not_ be used directly by developers outside
//! of Bolt Labs. It is designed as a dependency for other crates in the
//! ecosystem, including `lock-keeper-key-server` and `lock-keeper-client`.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod constants;
pub mod crypto;
pub mod error;
pub mod infrastructure;
pub mod types;

pub use error::LockKeeperError;

#[allow(clippy::all)]
pub mod rpc {
    tonic::include_proto!("lock_keeper_rpc");
}

/// Generates `TryFrom` implementations to and from the `Message` type for a
/// given list of types.
#[macro_export]
macro_rules! impl_message_conversion {
    ($($message_type:ty),+) => {
        $(
            impl TryFrom<$crate::types::Message> for $message_type {
                type Error = $crate::LockKeeperError;

                fn try_from(value: $crate::types::Message) -> Result<Self, Self::Error> {
                    Ok(serde_json::from_slice(&value.content)?)
                }
            }

            impl TryFrom<$message_type> for $crate::types::Message {
                type Error = $crate::LockKeeperError;

                fn try_from(value: $message_type) -> Result<Self, Self::Error> {
                    let content = serde_json::to_vec(&value)?;

                    Ok($crate::types::Message { content })
                }
            }

            impl $crate::infrastructure::channel::ShouldBeAuthenticated for $message_type {
                fn should_be_authenticated(&self) -> bool {
                    false
                }
            }
        )+
    };
}

/// Generates `TryFrom` implementations to and from the `Message` type for a
/// given list of types that should only be sent authenticated.
#[macro_export]
macro_rules! impl_authenticated_message_conversion {
    ($($message_type:ty),+) => {
        $(
            impl TryFrom<$crate::types::Message> for $message_type {
                type Error = $crate::LockKeeperError;

                fn try_from(value: $crate::types::Message) -> Result<Self, Self::Error> {
                    Ok(serde_json::from_slice(&value.content)?)
                }
            }

            impl TryFrom<$message_type> for $crate::types::Message {
                type Error = $crate::LockKeeperError;

                fn try_from(value: $message_type) -> Result<Self, Self::Error> {
                    let content = serde_json::to_vec(&value)?;

                    Ok($crate::types::Message { content })
                }
            }

            impl $crate::infrastructure::channel::ShouldBeAuthenticated for $message_type {
                fn should_be_authenticated(&self) -> bool {
                    true
                }
            }
        )+
    };
}
