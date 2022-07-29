use anyhow::Context;
use dams::{config::server::Config, defaults::server::config_path};
use dams_key_server::{cli, cli::Cli, command::Command, database};
use futures::FutureExt;
use mongodb::Database;
use std::convert::identity;
use structopt::StructOpt;

pub async fn main_with_cli(cli: Cli, db: Database) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load server configuration from {:?}", config_path))
    });

    use cli::Server::*;
    match cli.server {
        Run(run) => run.run(config.await?, db).await,
    }
}

#[allow(unused)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let db = database::connect_to_mongo().await?;
    main_with_cli(Cli::from_args(), db).await
}
