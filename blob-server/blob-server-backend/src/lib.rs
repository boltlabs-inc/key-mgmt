mod config;
mod database;
mod error;
mod helpers;
mod server;

pub use config::{Config, DatabaseConfig, DatabaseConfigFile};
pub use database::BlobServerDatabase;
pub use error::BlobServerError;
pub use server::start_blob_server;

#[allow(clippy::all)]
pub mod rpc {
    tonic::include_proto!("blob_server_rpc");
}
