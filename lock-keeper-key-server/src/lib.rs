//! This crate is an implementation of a key server to a key management system.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]
// Getting some weird Clippy warning that don't
// make sense. May be related to Clippy complaining
// about auto-generated code. Allow this.
#![allow(clippy::blocks_in_conditions)]
pub mod config;
pub mod error;
pub mod operations;
pub mod server;

pub use config::Config;
pub use error::LockKeeperServerError;
