use dams::transport::KeyMgmtAddress;
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
    Retrieve(Retrieve),
}

/// Create a secret.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Create {
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
