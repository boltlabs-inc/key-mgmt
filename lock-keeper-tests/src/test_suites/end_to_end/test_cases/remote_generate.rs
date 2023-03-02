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
    println!("{}", "Running remote generate tests".cyan());

    let result = run_parallel!(
        filters,
        remote_generate_works(config.clone()),
        cannot_remote_generate_after_logout(config.clone()),
    )?;

    Ok(result)
}

async fn remote_generate_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let remote_gen_res = client.remote_generate().await;
    let request_id = remote_gen_res.metadata.clone().unwrap().request_id;
    let key_id = remote_gen_res.result?.key_id;

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteGenerateSigningKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_remote_generate_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = client.remote_generate().await;
    assert!(matches!(
        res.result,
        Err(LockKeeperClientError::InvalidSession)
    ));

    Ok(())
}
