use anyhow::Context;
use dams::{config::server::Config, defaults::server::config_path};
use futures::FutureExt;
use key_server::{cli, cli::Cli, command::Command};
use std::convert::identity;
use structopt::StructOpt;

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load server configuration from {:?}", config_path))
    });

    use cli::Server::*;
    match cli.server {
        Run(run) => run.run(config.await?).await,
    }
}

#[allow(unused)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    main_with_cli(Cli::from_args()).await
}
