use anyhow::Context;
use futures::FutureExt;
use keymgmt::client::cli::Client::{Create, Retrieve};
use keymgmt::client::defaults::config_path;
use keymgmt::client::{Cli, Config};
use std::convert::identity;
use structopt::StructOpt;

pub async fn main_with_cli(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.config.ok_or_else(config_path).or_else(identity)?;
    let _config = Config::load(&config_path).map(|result| {
        result
            .with_context(|| format!("Could not load client configuration from {:?}", config_path))
    });

    match cli.client {
        Create(_run) => Ok(()),
        Retrieve(_run) => Ok(()),
    }
}

#[allow(unused)]
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    main_with_cli(Cli::from_args()).await
}
