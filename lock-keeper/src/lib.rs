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
