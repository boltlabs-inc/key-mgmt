//! This crate is an implementation of a key management system
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

use std::fmt;

pub mod client;
pub mod localclient;
pub mod protocol;
pub mod server;
pub mod timeout;
pub mod transport;

mod cli;
mod config;
// TODO (implementation): make this its own crate.
mod crypto;
mod defaults;
mod key_mgmt;
mod keys;
mod transaction;

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
