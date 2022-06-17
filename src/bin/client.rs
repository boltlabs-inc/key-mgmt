use anyhow::Context;
use da_mgmt::client::key_mgmt::Command;
use da_mgmt::client::{
    cli::Client::{Create, Retrieve},
    defaults::config_path,
    Cli, Config,
};
use futures::FutureExt;
use std::convert::identity;
use structopt::StructOpt;

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load client configuration from {:?}", config_path))
    });

    match cli.client {
        Create(create) => create.run(config.await?).await,
        Retrieve(retrieve) => {
            println!("{:?}", retrieve.run(config.await?).await?);
            Ok(())
        }
    }
}

#[allow(unused)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    main_with_cli(Cli::from_args()).await
}
