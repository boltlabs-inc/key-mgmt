use crate::transport::KeyMgmtAddress;
use std::path::PathBuf;
use structopt::StructOpt;

/// The keyMgmt client command-line interface.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Cli {
    /// Path to a configuration file.
    #[structopt(long)]
    pub config: Option<PathBuf>,

    /// Run client commands.
    #[structopt(subcommand)]
    pub client: Client,
}

#[derive(Debug, StructOpt)]
pub enum Client {
    Create(Create),
    Register(Register),
    Retrieve(Retrieve),
}

/// Create a secret.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Create {
    /// The `keymgmt://` address for the server.
    pub server: KeyMgmtAddress,
}

/// Register using OPAQUE.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Register {
    /// The username to register
    #[structopt(long)]
    pub username: String,
    /// The password to register
    #[structopt(long)]
    pub password: String,
    /// The `keymgmt://` address for the server.
    pub server: KeyMgmtAddress,
}

/// Retrieve a secret.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Retrieve {
    /// The `keymgmt://` address for the server.
    pub server: KeyMgmtAddress,
}
