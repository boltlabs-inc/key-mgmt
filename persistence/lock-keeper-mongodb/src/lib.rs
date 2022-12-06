//! This crate is an implementation of a database for a key server.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod error;

pub(crate) mod constants;

pub use api::Database;
