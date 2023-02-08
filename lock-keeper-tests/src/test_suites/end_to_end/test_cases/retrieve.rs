use colored::Colorize;
use lock_keeper::types::{
    audit_event::EventStatus,
    operations::{retrieve_secret::RetrieveContext, ClientAction},
};
use lock_keeper_client::{api::GenerateResult, Config};
use rand::Rng;
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{
            authenticate, check_audit_events, compare_errors, compare_status_errors,
            generate_fake_key_id,
        },
        test_cases::{init_test_state, NO_ENTRY_FOUND, NO_SESSION},
    },
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running retrieve tests".cyan());

    let result = run_parallel!(
        filters,
        retrieve_local_only_works(config.clone()),
        retrieve_null_works(config.clone()),
        cannot_retrieve_fake_key(config.clone()),
        cannot_retrieve_after_logout(config.clone()),
        store_retrieve_server_encrypted_blob(config.clone()),
        blob_size_too_large(config.clone()),
    )?;

    Ok(result)
}

/// Create a client-generated secret via `generate_secret`.
/// Fetch the secret back out and ensure the material matches what we stored.
/// Check the audit events for a successful retrieval.
async fn retrieve_local_only_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let GenerateResult {
        key_id,
        local_storage,
    } = client.generate_secret().await.result?;
    let local_storage_res = client
        .retrieve_secret(&key_id, RetrieveContext::LocalOnly)
        .await;

    let local_storage_opt = local_storage_res.result?;
    let request_id = local_storage_res.metadata.clone().unwrap().request_id;

    let local_storage_new = local_storage_opt.unwrap();
    assert_eq!(local_storage_new.material, local_storage.material);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RetrieveSecret,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn retrieve_null_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await.result?;
    let local_storage_res = client.retrieve_secret(&key_id, RetrieveContext::Null).await;

    let local_storage_opt = local_storage_res.result?;
    let request_id = local_storage_res.metadata.unwrap().request_id;
    assert!(local_storage_opt.is_none());
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RetrieveSecret,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_retrieve_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let local_storage_res = client
        .retrieve_secret(&fake_key_id, RetrieveContext::LocalOnly)
        .await;
    let request_id = local_storage_res.metadata.clone().unwrap().request_id;
    compare_errors(local_storage_res, Status::internal(NO_ENTRY_FOUND));
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::RetrieveSecret,
        request_id,
        Some(fake_key_id),
    )
    .await?;

    Ok(())
}

async fn cannot_retrieve_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    // Generate a secret before waiting out the timeout
    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await.result?;
    client.logout().await.result?;

    let res = client.retrieve_secret(&key_id, RetrieveContext::Null).await;
    compare_status_errors(res, Status::unauthenticated(NO_SESSION))?;

    Ok(())
}

/// Tests our server encrypted blob functionality by storing and retrieving a
/// data blob.
async fn store_retrieve_server_encrypted_blob(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;
    let data: Vec<u8> = std::iter::repeat_with(|| rand::thread_rng().gen())
        .take(512)
        .collect();

    // Store blob and check audit events.
    let server_response = client.store_server_encrypted_blob(data.clone()).await;
    let key_id = server_response.result?;
    let request_id = server_response.metadata.clone().unwrap().request_id;

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::StoreServerEncryptedBlob,
        request_id,
        Some(key_id.clone()),
    )
    .await?;

    // Retrieved store blob, check data matches what we stored and audit events.
    let lk_response = client.retrieve_server_encrypted_blob(&key_id).await;
    let retrieved_blob = lk_response.result?;
    let request_id = lk_response.metadata.clone().unwrap().request_id;

    assert_eq!(data, retrieved_blob);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RetrieveServerEncryptedBlob,
        request_id,
        Some(key_id),
    )
    .await?;

    Ok(())
}

/// Trying to store a too-large data blob will result in server error.
async fn blob_size_too_large(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;
    // Our testing server is configured to accept a max blob size of 1024.
    let data_blob = vec![24; 1025];

    // Store blob and check audit events.
    let server_response = client.store_server_encrypted_blob(data_blob.clone()).await;
    assert!(
        server_response.result.is_err(),
        "Server should return error due to too large blob size "
    );

    let request_id = server_response.metadata.clone().unwrap().request_id;
    check_audit_events(
        &state,
        EventStatus::Failed,
        ClientAction::StoreServerEncryptedBlob,
        request_id,
        None,
    )
    .await?;

    Ok(())
}
