pub mod end_to_end;

use clap::Parser;
use lock_keeper::config::client::Config;
use lock_keeper_client::LockKeeperClient;
use std::{path::PathBuf, time::Duration};

use end_to_end::end_to_end_tests;

const NUM_RETRIES: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
pub struct Cli {
    pub client_config: PathBuf,
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let config = Config::load(&cli.client_config).await.unwrap();
    wait_for_server(&config).await;
    end_to_end_tests(&config).await;
}

async fn wait_for_server(config: &Config) {
    for i in 0..NUM_RETRIES {
        println!("Attempting to connect to server...");
        match LockKeeperClient::health(config).await {
            Ok(_) => return,
            Err(_) => {
                println!("Server connection failed. Retrying in {:?}", RETRY_DELAY);
                if i == 0 {
                    println!("Did you remember to run `cargo make run-server`?")
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }

    panic!("Failed to connect to server.");
}
