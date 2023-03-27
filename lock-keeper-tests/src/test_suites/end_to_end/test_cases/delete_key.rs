use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::Config;
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, compare_errors, generate_fake_key_id},
        test_cases::{init_test_state, NO_ENTRY_FOUND},
    },
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running delete key tests".cyan());

    let result = run_parallel!(
        filters,
        can_delete_arbitrary_secret(config.clone()),
        can_delete_signing_key(config.clone()),
        cannot_delete_another_users_key(config.clone()),
        cannot_delete_fake_key(config.clone()),
    )?;

    Ok(result)
}

async fn can_delete_arbitrary_secret(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let generate_result = client.generate_secret().await;
    let key_id = generate_result.result?.key_id;

    let delete_result = client.delete_key(&key_id).await;
    let request_id = delete_result.metadata.unwrap().request_id;

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::DeleteKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn can_delete_signing_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let remote_generate_result = client.remote_generate().await;
    let key_id = remote_generate_result.result?.key_id;

    let delete_result = client.delete_key(&key_id).await;
    let request_id = delete_result.metadata.unwrap().request_id;

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::DeleteKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_delete_another_users_key(config: Config) -> Result<()> {
    // Login as one client and generate a key
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;
    let generate_result = client.generate_secret().await;
    let key_id = generate_result.result?.key_id;

    // Login as a different client and try to delete that key
    let different_state = init_test_state(&config).await?;
    let different_client = authenticate(&different_state).await.result?;
    let delete_result = different_client.delete_key(&key_id).await;
    let request_id = delete_result.metadata.clone().unwrap().request_id;

    compare_errors(delete_result, Status::internal(NO_ENTRY_FOUND));
    check_audit_events(
        &different_state,
        EventStatus::Failed,
        ClientAction::DeleteKey,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_delete_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let delete_result = client.delete_key(&fake_key_id).await;
    let request_id = delete_result.metadata.clone().unwrap().request_id;
    compare_errors(delete_result, Status::internal(NO_ENTRY_FOUND));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::DeleteKey,
        request_id,
        Some(fake_key_id),
    )
    .await?;

    Ok(())
}
