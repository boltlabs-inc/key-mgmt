//! Command-line arguments

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Cli {
    /// Location of client config file.
    #[clap(long, default_value = "dev/local/Client.toml")]
    pub config: PathBuf,
    /// Directory where persistent storage files will be saved.
    #[clap(long, default_value = "dev/lk_client_cli_data")]
    pub storage_path: PathBuf,
}
