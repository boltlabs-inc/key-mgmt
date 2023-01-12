//! This crate is an implementation of a session key cache for a key server.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod config;
pub mod error;
pub mod types;

pub use api::PostgresSessionCache;
pub use error::Error;
