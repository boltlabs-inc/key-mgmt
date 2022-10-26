mod app;
mod cli;
mod cli_command;
mod state;
mod storage;

use clap::Parser;
use lock_keeper_client::Config;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
pub async fn main() {
    let cli = cli::Cli::parse();
    let config = Config::from_file(&cli.config, None).unwrap();

    tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();
    info!("Starting client CLI ");

    app::run(config, cli.storage_path).await.unwrap();
}
