mod app;
mod cli;
mod cli_command;
mod scripting;
mod state;
mod storage;

use std::str::FromStr;

use clap::Parser;
use lock_keeper_client::Config;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::scripting::Script;

#[tokio::main]
pub async fn main() {
    let cli = cli::Cli::parse();
    let config = Config::from_file(&cli.config, None).unwrap();
    let script = parse_script(&cli).unwrap();

    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    info!("Starting client CLI ");

    match script {
        Some(script) => app::run_script(config, cli.storage_path, script)
            .await
            .unwrap(),
        None => app::run(config, cli.storage_path).await.unwrap(),
    }
}

fn parse_script(cli: &cli::Cli) -> anyhow::Result<Option<Script>> {
    if let Some(script_file) = &cli.script_file {
        Ok(Some(Script::from_file(script_file)?))
    } else if let Some(script) = &cli.script {
        Ok(Some(Script::from_str(script)?))
    } else {
        Ok(None)
    }
}
