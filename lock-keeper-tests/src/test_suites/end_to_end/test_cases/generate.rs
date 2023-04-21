use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::{Config, LockKeeperClientError};

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events},
        test_cases::init_test_state,
    },
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running generate tests".cyan());

    let result = run_parallel!(
        filters,
        generate_works(config.clone()),
        cannot_generate_after_logout(config.clone())
    )?;

    Ok(result)
}

async fn generate_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let generate_result = client.generate_secret().await;
    let request_id = generate_result.metadata.unwrap().request_id;
    let key_id = generate_result.result?.key_id;
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::GenerateSecret,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_generate_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = client.generate_secret().await;
    assert!(matches!(
        res.result,
        Err(LockKeeperClientError::InvalidSession)
    ));

    Ok(())
}
