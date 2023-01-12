//! This crate is an implementation of a client to a key management system.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod channel;
pub mod client;
pub mod config;
pub mod error;
pub mod response;

pub use client::LockKeeperClient;
pub use config::Config;
pub use error::{LockKeeperClientError, Result};
pub use response::LockKeeperResponse;
