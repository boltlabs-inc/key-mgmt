//! This crate is an implementation of a key server to a key management system.
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod cli;
pub mod command;
pub mod database;
pub mod error;
pub mod policy_engine;
pub mod server;

pub(crate) mod constants;

pub use error::DamsServerError;
