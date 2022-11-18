use colored::Colorize;
use lock_keeper::types::{
    audit_event::EventStatus,
    operations::{retrieve::RetrieveContext, ClientAction},
};
use lock_keeper_client::Config;
use tonic::Status;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{
            check_audit_events, compare_errors, generate, generate_fake_key_id, retrieve,
        },
        test_cases::init_test_state,
    },
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running retrieve tests".cyan());

    let result = run_parallel!(
        config.clone(),
        retrieve_local_only_works(config.client_config.clone()),
        retrieve_null_works(config.client_config.clone()),
        cannot_retrieve_fake_key(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn retrieve_local_only_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, local_storage) = generate(&state).await?;
    let local_storage_res = retrieve(&state, &key_id, RetrieveContext::LocalOnly).await;
    assert!(local_storage_res.is_ok());

    let local_storage_opt = local_storage_res?;
    assert!(local_storage_opt.is_some());

    let local_storage_new = local_storage_opt.unwrap();
    assert_eq!(local_storage_new.material, local_storage.material);
    check_audit_events(&state, EventStatus::Successful, ClientAction::Retrieve).await?;

    Ok(())
}

async fn retrieve_null_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let (key_id, _) = generate(&state).await?;
    let local_storage_res = retrieve(&state, &key_id, RetrieveContext::Null).await;
    assert!(local_storage_res.is_ok());

    let local_storage_opt = local_storage_res?;
    assert!(local_storage_opt.is_none());
    check_audit_events(&state, EventStatus::Successful, ClientAction::Retrieve).await?;

    Ok(())
}

async fn cannot_retrieve_fake_key(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let fake_key_id = generate_fake_key_id(&state).await?;
    let local_storage_res = retrieve(&state, &fake_key_id, RetrieveContext::LocalOnly).await;
    compare_errors(local_storage_res, Status::internal("Internal server error"));
    check_audit_events(&state, EventStatus::Failed, ClientAction::Retrieve).await?;

    Ok(())
}
