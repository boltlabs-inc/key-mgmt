pub mod config;
pub mod database;
pub mod end_to_end;
pub mod utils;

use clap::Parser;
use config::Config;
use lock_keeper_client::LockKeeperClient;
use std::{path::PathBuf, str::FromStr, time::Duration};

const NUM_RETRIES: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(default_value = "./dev/local/Client.toml")]
    pub client_config: PathBuf,
    #[clap(long = "filter")]
    pub filters: Option<Vec<String>>,
    #[clap(long, default_value = "all")]
    pub test_type: TestType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestType {
    All,
    E2E,
    Integration,
}

impl FromStr for TestType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(TestType::All),
            "e2e" => Ok(TestType::E2E),
            "integration" => Ok(TestType::Integration),
            _ => anyhow::bail!("Invalid test type: {}", s),
        }
    }
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let test_type = cli.test_type;
    let config = Config::try_from(cli).unwrap();
    wait_for_server(&config).await;

    match test_type {
        TestType::All => {
            database::run_tests(&config).await.unwrap();
            end_to_end::run_tests(&config).await.unwrap();
        }
        TestType::E2E => {
            end_to_end::run_tests(&config).await.unwrap();
        }
        TestType::Integration => {
            database::run_tests(&config).await.unwrap();
        }
    }
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
