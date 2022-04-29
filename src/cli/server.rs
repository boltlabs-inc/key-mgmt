use std::path::PathBuf;
use structopt::StructOpt;

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
