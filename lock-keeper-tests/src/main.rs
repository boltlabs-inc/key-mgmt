pub mod config;
pub mod error;
pub mod test_suites;
pub mod utils;

use crate::error::LockKeeperTestError;
use clap::Parser;
use config::Config;
use std::{path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(default_value = "./dev/local/Client.toml")]
    pub client_config: PathBuf,
    #[clap(default_value = "./dev/local/ClientMutualAuth.toml")]
    pub mutual_auth_client_config: PathBuf,
    #[clap(long = "filter")]
    pub filters: Option<Vec<String>>,
    #[clap(long, default_value = "all")]
    pub test_type: TestType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestType {
    All,
    ConfigFiles,
    E2E,
    Integration,
    MutualAuth,
}

impl FromStr for TestType {
    type Err = LockKeeperTestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(TestType::All),
            "config-files" => Ok(TestType::ConfigFiles),
            "e2e" => Ok(TestType::E2E),
            "integration" => Ok(TestType::Integration),
            "mutual-auth" => Ok(TestType::MutualAuth),
            _ => Err(LockKeeperTestError::InvalidTestType(s.to_string())),
        }
    }
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let test_type = cli.test_type;
    let config = Config::try_from(cli).unwrap();
    utils::wait_for_server(&config.client_config).await.unwrap();

    match test_type {
        TestType::All => {
            test_suites::run_all(&config).await.unwrap();
        }
        TestType::ConfigFiles => {
            test_suites::config_files::run_tests(&config).await.unwrap();
        }
        TestType::E2E => {
            test_suites::end_to_end::run_tests(&config).await.unwrap();
        }
        TestType::Integration => {
            test_suites::database::run_tests(&config).await.unwrap();
        }
        TestType::MutualAuth => {
            test_suites::mutual_auth::run_tests(&config).await.unwrap();
        }
    }
}
