use colored::Colorize;
use lock_keeper::types::{
    audit_event::EventStatus,
    operations::{retrieve_secret::RetrieveContext, ClientAction},
};
use lock_keeper_client::{api::GenerateResult, Config};
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
        test_cases::init_test_state,
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
    )?;

    Ok(result)
}

async fn retrieve_local_only_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await?;

    let GenerateResult {
        key_id,
        local_storage,
    } = client.generate_secret().await?.into_inner();
    let local_storage_res = client
        .retrieve_secret(&key_id, RetrieveContext::LocalOnly)
        .await;
    assert!(local_storage_res.is_ok());

    let local_storage_opt = local_storage_res?.into_inner();
    assert!(local_storage_opt.is_some());

    let local_storage_new = local_storage_opt.unwrap();
    assert_eq!(local_storage_new.material, local_storage.material);
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RetrieveSecret,
    )
    .await?;

    Ok(())
}

async fn retrieve_null_works(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await?;

    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await?.into_inner();
    let local_storage_res = client.retrieve_secret(&key_id, RetrieveContext::Null).await;
    assert!(local_storage_res.is_ok());

    let local_storage_opt = local_storage_res?.into_inner();
    assert!(local_storage_opt.is_none());
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RetrieveSecret,
    )
    .await?;

    Ok(())
}

async fn cannot_retrieve_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await?;

    let fake_key_id = generate_fake_key_id(&client).await?;
    let local_storage_res = client
        .retrieve_secret(&fake_key_id, RetrieveContext::LocalOnly)
        .await;
    compare_errors(local_storage_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::RetrieveSecret).await?;

    Ok(())
}

async fn cannot_retrieve_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await?;

    // Generate a secret before waiting out the timeout
    let GenerateResult {
        key_id,
        local_storage: _,
    } = client.generate_secret().await?.into_inner();
    client.logout().await?;

    let res = client.retrieve_secret(&key_id, RetrieveContext::Null).await;
    compare_status_errors(res, Status::unauthenticated("No session key for this user"))?;

    Ok(())
}
