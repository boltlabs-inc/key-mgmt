pub mod config;
pub mod end_to_end;

use clap::Parser;
use config::Config;
use lock_keeper_client::LockKeeperClient;
use std::{path::PathBuf, time::Duration};

use end_to_end::end_to_end_tests;

const NUM_RETRIES: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(default_value = "./dev/local/Client.toml")]
    pub client_config: PathBuf,
    #[clap(long = "filter")]
    pub filters: Option<Vec<String>>,
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let config = Config::try_from(cli).unwrap();
    wait_for_server(&config).await;
    end_to_end_tests(&config).await;
}

async fn wait_for_server(config: &Config) {
    for i in 0..NUM_RETRIES {
        println!("Attempting to connect to server...");
        match LockKeeperClient::health(&config.client_config).await {
            Ok(_) => return,
            Err(_) => {
                println!("Server connection failed. Retrying in {:?}", RETRY_DELAY);
                if i == 0 {
                    println!("Did you remember to run `cargo make start`?")
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }

    panic!("Failed to connect to server.");
}
