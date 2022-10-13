use std::path::PathBuf;

use clap::Parser;
use lock_keeper::config::server::Config;
use lock_keeper_key_server::server::start_lock_keeper_server;

#[derive(Debug, Parser)]
pub struct Cli {
    pub config: PathBuf,
}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();

    let config = Config::load(&cli.config).await.unwrap();
    start_lock_keeper_server(config).await.unwrap();
}
