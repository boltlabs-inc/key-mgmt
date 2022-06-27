//! This crate is an implementation of a key management system
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

use std::fmt;

pub mod blockchain;
pub mod client;
pub mod keys;
pub mod localclient;
pub mod protocol;
pub mod remote_client;
pub mod server;
pub mod timeout;
pub mod transaction;
pub mod transport;

mod cli;
mod config;
mod defaults;
mod key_mgmt;

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
