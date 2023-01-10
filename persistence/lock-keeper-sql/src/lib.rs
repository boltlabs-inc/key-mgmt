//! This crate is an implementation of a PostgreSQL database for the key server.
//! We use SQLx to connect and implement queries for our DB. See .sql file on
//! the root folder of this crate for the schema and other table set-up
//! commands.
//!
//! We use static, string-literal queries whenever possible (since they checked
//! at compile time by SQLx. This is not always possible, so we may also use the
//! QueryBuilder API from SQLx for dynamically generated queries which are not
//! checked at compile time. We also use the *_as version of SQLX macros when
//! possible. E.g. `query_as!`, since these versions automatically convert query
//! results into the provided Rust type (this is typed checked by SQLx based on
//! the inferred types of the query).
//!
//!
//! SQLx connects to a postgres database at compile time to query the schema and
//! ensure all the types match. This is specified via the `DATABASE_URL` when
//! `cargo build` or `cargo check` (etc.) the project. For example:
//! `DATABASE_URL='postgres://username:password@localhost/db_name' cargo run
//! --bin key-server-cli ...`. *Important:** This is only necessary if you are
//! planning to make change to any of our compile-time checked queries.
//! Otherwise SQLx will use our pre-generated `sqlx-data.json` file. This
//! ensures we don't always need a live postgres server running to compile the
//! project.
//!
//! The DATABASE_URL variable, if present, overrides the `sqlx-data.json` file.
//! If you make any changes to the queries or schema, you must re-generate the
//! `sqlx-data.json` file. Via the `sqlx-cli`. See [Offline Mode](https://docs.rs/sqlx/latest/sqlx/macro.query.html#offline-mode-requires-the-offline-feature)
//! for more information.
//!
//! `sqlx-cli` can be installed locally with `cargo install sqlx-cli
//! --no-default-features --features native-tls,postgres` Then the
//! `sqlx-data.json` file was generated using `cargo sqlx prepare --database-url
//! YOUR_DATABASE_URI --merged`. The `--merged` option should be used to handle
//! our project being a cargo workspace.
#![warn(unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

mod api;
mod config;
mod error;
mod types;

pub use api::PostgresDB;
pub use config::{Config, ConfigFile};
pub use error::PostgresError;
