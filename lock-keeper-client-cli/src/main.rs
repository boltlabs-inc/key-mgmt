mod app;
mod cli;
mod command;
mod state;
mod storage;

use clap::Parser;
use lock_keeper::config::client::Config;

#[tokio::main]
pub async fn main() {
    let cli = cli::Cli::parse();
    let config = Config::load(&cli.config).unwrap();

    app::run(config, cli.storage_path).await.unwrap();
}
