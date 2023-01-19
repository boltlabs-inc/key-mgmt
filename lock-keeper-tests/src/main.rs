pub mod config;
pub mod error;
pub mod test_suites;
pub mod utils;

use crate::{
    error::LockKeeperTestError,
    utils::{report_test_results, TestResult},
};
use clap::Parser;
use colored::Colorize;
use config::Environments;
use std::{path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(long, default_value = "./dev/config/TestEnvironments.toml")]
    pub environments: PathBuf,
    #[clap(long = "filter")]
    pub filters: Option<Vec<String>>,
    #[clap(long, default_value = "all")]
    pub test_type: TestType,
    #[clap(long, short = 's')]
    pub standard_only: bool,
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
    // Run tests and print nice errors if any occur.
    if let Err(e) = run().await {
        eprintln!("{}", e.to_string().red());
        std::process::exit(1);
    }
}

async fn run() -> Result<(), LockKeeperTestError> {
    let cli = Cli::try_parse()?;
    if cli.standard_only && cli.test_type != TestType::E2E {
        return Err(LockKeeperTestError::StandardOnlyFlag);
    }

    let test_type = cli.test_type;
    let environments = Environments::try_from(cli)?;

    environments.wait().await?;

    match run_tests(test_type, environments).await {
        Err(e @ LockKeeperTestError::TestFailed) => {
            // Manually report error to avoid a useless stack trace
            eprintln!("{}", e.to_string().red());
            std::process::exit(1);
        }
        Err(e) => {
            // TODO: Without this, error message is not printed.
            eprintln!("{}", e.to_string().red());
            panic!("{e}")
        }
        _ => (),
    }

    Ok(())
}

async fn run_tests(
    test_type: TestType,
    environments: Environments,
) -> Result<(), LockKeeperTestError> {
    let results = match test_type {
        TestType::All => {
            let integration_results = run_integration_tests(&environments).await?;
            let e2e_results = test_suites::end_to_end::run_tests(&environments).await?;

            [integration_results, e2e_results].concat()
        }
        TestType::E2E => test_suites::end_to_end::run_tests(&environments).await?,
        TestType::Integration => run_integration_tests(&environments).await?,
    };

    if results.iter().any(|r| *r == TestResult::Failed) {
        Err(LockKeeperTestError::TestFailed)
    } else {
        Ok(())
    }
}

async fn run_integration_tests(
    environments: &Environments,
) -> Result<Vec<TestResult>, LockKeeperTestError> {
    let client_auth_results = test_suites::client_auth::run_tests(environments).await?;
    let config_file_results = test_suites::config_files::run_tests(&environments.filters).await?;
    let database_results = test_suites::database::run_tests(&environments.filters).await?;
    let session_cache_results =
        test_suites::session_cache::run_tests(&environments.filters).await?;

    println!(
        "client auth tests: {}",
        report_test_results(&client_auth_results)
    );
    println!(
        "config file tests: {}",
        report_test_results(&config_file_results)
    );
    println!("database tests: {}", report_test_results(&database_results));
    println!(
        "session cache tests: {}",
        report_test_results(&session_cache_results)
    );

    Ok([config_file_results, database_results, client_auth_results].concat())
}
