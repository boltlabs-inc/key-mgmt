pub mod config;
pub mod error;
pub mod test_suites;
pub mod utils;

use crate::{error::LockKeeperTestError, utils::TestResult};
use clap::Parser;
use colored::Colorize;
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
    E2E,
    Integration,
}

impl FromStr for TestType {
    type Err = LockKeeperTestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(TestType::All),
            "e2e" => Ok(TestType::E2E),
            "integration" => Ok(TestType::Integration),
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

    match run_tests(test_type, config).await {
        Err(e @ LockKeeperTestError::TestFailed) => {
            // Manually report error to avoid a useless stack trace
            eprintln!("{}", e.to_string().red());
            std::process::exit(1);
        }
        Err(e) => panic!("{e}"),
        Ok(()) => (),
    }
}

async fn run_tests(test_type: TestType, config: Config) -> Result<(), LockKeeperTestError> {
    let results = match test_type {
        TestType::All => test_suites::run_all(&config).await?,
        TestType::E2E => test_suites::end_to_end::run_tests(&config).await?,
        TestType::Integration => {
            let mut results = Vec::new();

            results.extend(test_suites::config_files::run_tests(&config).await?);
            results.extend(test_suites::database::run_tests(&config).await?);
            results.extend(test_suites::mutual_auth::run_tests(&config).await?);

            results
        }
    };

    if results.iter().any(|r| *r == TestResult::Failed) {
        Err(LockKeeperTestError::TestFailed)
    } else {
        Ok(())
    }
}
