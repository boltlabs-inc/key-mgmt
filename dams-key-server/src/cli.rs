use dams::{config::server::Config, defaults::server::config_path};
use std::{convert::identity, path::PathBuf};
use structopt::StructOpt;

use crate::{server::start_dams_server, DamsServerError};

/// The keyMgmt server command-line interface.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Cli {
    /// Path to a configuration file.
    #[structopt(long)]
    pub config: Option<PathBuf>,

    /// Run server commands.
    #[structopt(subcommand)]
    pub server: Server,
}

#[derive(Debug, StructOpt)]
pub enum Server {
    Run(Run),
}

/// Run the server.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Run {}

impl Cli {
    pub async fn run(self) -> Result<(), DamsServerError> {
        let config_path = self.config.ok_or_else(config_path).or_else(identity)?;
        let config = Config::load(&config_path).await?;
        start_dams_server(config).await
    }
}
