//! TLS client authentication tests

use colored::Colorize;
use lock_keeper_client::{LockKeeperClient, LockKeeperClientError};

use crate::{
    config::Environments,
    error::Result,
    run_parallel,
    utils::{report_test_results, TestResult},
};

pub async fn run_tests(environments: &Environments) -> Result<Vec<TestResult>> {
    println!("{}", "Running client auth tests".cyan());

    let results = run_parallel!(
        &environments.filters,
        client_auth_not_required(environments.clone()),
        client_auth_required(environments.clone()),
        client_auth_required_not_provided(environments.clone()),
        client_auth_not_required_but_provided(environments.clone()),
    )?;

    println!("client auth tests: {}", report_test_results(&results));

    Ok(results)
}

async fn client_auth_not_required(environments: Environments) -> Result<()> {
    let result = LockKeeperClient::health(environments.standard_config()?).await;
    assert!(result.is_ok());

    Ok(())
}

async fn client_auth_required(environments: Environments) -> Result<()> {
    let result = LockKeeperClient::health(environments.client_auth_config()?).await;
    assert!(result.is_ok());

    Ok(())
}

async fn client_auth_required_not_provided(environments: Environments) -> Result<()> {
    // Point to client auth server but remove auth from client
    let mut client_config = environments.client_auth_config()?.clone();
    client_config.tls_config = environments.standard_config()?.tls_config.clone();

    let result = LockKeeperClient::health(&client_config).await;
    assert!(
        matches!(result, Err(LockKeeperClientError::ClientAuthMissing)),
        "{:?}",
        result.unwrap_err()
    );

    Ok(())
}

async fn client_auth_not_required_but_provided(environments: Environments) -> Result<()> {
    // Point to no auth client but add auth
    let mut client_config = environments.standard_config()?.clone();
    client_config.tls_config = environments.client_auth_config()?.tls_config.clone();

    let result = LockKeeperClient::health(&client_config).await;
    assert!(result.is_ok());

    Ok(())
}
