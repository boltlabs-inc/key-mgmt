use std::path::PathBuf;

use clap::Parser;
use lock_keeper::config::server::Config;
use lock_keeper_key_server::server::start_lock_keeper_server;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
pub struct Cli {
    pub config: PathBuf,
}

#[tokio::main]
pub async fn main() {
    let filter = EnvFilter::try_new("info,sqlx::query=warn").unwrap();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();

    let config = Config::load(&cli.config).await.unwrap();
    start_lock_keeper_server(config).await.unwrap();
}
