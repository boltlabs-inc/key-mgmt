use std::path::PathBuf;

use clap::Parser;
use lk_session_hashmap::HashmapKeyCache;
use lock_keeper_key_server::{config::Config, server::start_lock_keeper_server};
use lock_keeper_mongodb::Database;

#[derive(Debug, Parser)]
pub struct Cli {
    /// Path to the server config file
    pub config: PathBuf,
    /// Base64 encoded private key data
    #[clap(long)]
    pub private_key: Option<String>,
}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt().init();
    let cli = Cli::parse();
    let private_key_bytes = cli
        .private_key
        .map(String::into_bytes)
        .map(base64::decode)
        .transpose()
        .unwrap();

    let config = Config::from_file(&cli.config, private_key_bytes).unwrap();

    let mongo = Database::connect(&config.database).await.unwrap();
    let hashmap_cache = HashmapKeyCache::new(config.session_timeout);
    start_lock_keeper_server(config, mongo, hashmap_cache)
        .await
        .unwrap();
}
