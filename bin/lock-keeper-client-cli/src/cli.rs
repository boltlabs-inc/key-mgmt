//! Command-line arguments

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Cli {
    /// Location of client config file.
    #[clap(long, default_value = "./dev/config/local/Client.toml")]
    pub config: PathBuf,
    /// Directory where persistent storage files will be saved.
    #[clap(long, default_value = "dev/lk_client_cli_data")]
    pub storage_path: PathBuf,
    /// Path to a script file containing a sequence of CLI commands
    #[clap(long = "script-file", conflicts_with = "script")]
    pub script_file: Option<PathBuf>,
    /// Sequence of CLI commands separated by a semicolon or newline
    #[clap(long, conflicts_with = "script-file")]
    pub script: Option<String>,
}
