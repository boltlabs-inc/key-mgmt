//! This crate is an implementation of a session key cache for a key server.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

pub mod api;

pub use api::HashmapKeyCache;
