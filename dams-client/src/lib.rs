//! This crate is an implementation of a client to a key management system.
#![warn(missing_debug_implementations)]
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod api;
pub mod error;

pub use error::DamsClientError;
