use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::{Config, LockKeeperClientError};

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, import_signing_key},
        test_cases::init_test_state,
    },
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running import tests".cyan());

    let result = run_parallel!(
        filters,
        import_works(config.clone()),
        cannot_import_after_logout(config.clone())
    )?;

    Ok(result)
}

async fn import_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let import_res = import_signing_key(&client).await;
    let request_id = import_res.metadata.unwrap().request_id;
    let key_id = import_res.result?.0;
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ImportSigningKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_import_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = import_signing_key(&client).await;
    assert!(matches!(
        res.result,
        Err(LockKeeperClientError::InvalidSession)
    ));

    Ok(())
}
