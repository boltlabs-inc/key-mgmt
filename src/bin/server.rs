use anyhow::{anyhow, Context};
use futures::FutureExt;
use keymgmt::server::defaults::config_path;
use keymgmt::server::keymgmt::Command;
use keymgmt::server::{cli, Cli, Config};
use std::convert::identity;
use structopt::StructOpt;
use thiserror::Error;

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load server configuration from {:?}", config_path))
    });

    use cli::Server::*;
    match cli.server {
        Run(run) => run.run(config.await?).await,
        _ => Err(anyhow!(CliError::NotImplemented)),
    }
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Command not implemented")]
    NotImplemented,
}

#[allow(unused)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    main_with_cli(Cli::from_args()).await
}
