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
    Placeholder(Placeholder),
    Run(Run),
}

/// TODO: A Placeholder option to make tests run for now.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Placeholder {}

/// Run the server.
#[derive(Debug, StructOpt)]
#[non_exhaustive]
pub struct Run {}
