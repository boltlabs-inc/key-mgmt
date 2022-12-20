//! TLS client authentication tests

use colored::Colorize;
use lock_keeper_client::{LockKeeperClient, LockKeeperClientError};

use crate::{
    config::Config,
    error::Result,
    run_parallel,
    test_suites::database::TestDatabase,
    utils::{report_test_results, wait_for_server, TestResult},
};

pub async fn run_tests(config: &Config) -> Result<Vec<TestResult>> {
    println!("Checking that client auth enabled server is running...");
    wait_for_server(&config.client_auth_client_config).await?;

    println!("{}", "Running client auth tests".cyan());

    let db = TestDatabase::new("client_auth_tests").await?;
    let results = run_parallel!(
        config.clone(),
        client_auth_not_required(config.clone()),
        client_auth_required(config.clone()),
        client_auth_required_not_provided(config.clone()),
        client_auth_not_required_but_provided(config.clone()),
    )?;

    db.drop().await?;

    println!("client auth tests: {}", report_test_results(&results));

    Ok(results)
}

async fn client_auth_not_required(config: Config) -> Result<()> {
    let result = LockKeeperClient::health(&config.client_config).await;
    assert!(result.is_ok());

    Ok(())
}

async fn client_auth_required(config: Config) -> Result<()> {
    let result = LockKeeperClient::health(&config.client_auth_client_config).await;
    assert!(result.is_ok());

    Ok(())
}

async fn client_auth_required_not_provided(config: Config) -> Result<()> {
    // Point to client auth server but remove auth from client
    let mut client_config = config.client_auth_client_config;
    client_config.tls_config = config.client_config.tls_config;

    let result = LockKeeperClient::health(&client_config).await;
    assert!(
        matches!(result, Err(LockKeeperClientError::ClientAuthMissing)),
        "{:?}",
        result.unwrap_err()
    );

    Ok(())
}

async fn client_auth_not_required_but_provided(config: Config) -> Result<()> {
    // Point to no auth client but add auth
    let mut client_config = config.client_config;
    client_config.tls_config = config.client_auth_client_config.tls_config;

    let result = LockKeeperClient::health(&client_config).await;
    assert!(result.is_ok());

    Ok(())
}
