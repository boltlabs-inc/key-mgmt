use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::Config;
use tonic::Status;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, compare_status_errors},
        test_cases::init_test_state,
    },
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running remote generate tests".cyan());

    let result = run_parallel!(
        config.clone(),
        remote_generate_works(config.client_config.clone()),
        cannot_remote_generate_after_logout(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn remote_generate_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    let remote_gen_res = client.remote_generate().await;
    assert!(remote_gen_res.is_ok());

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteGenerateSigningKey,
    )
    .await?;

    Ok(())
}

async fn cannot_remote_generate_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;
    let client = authenticate(&state).await?;

    client.logout().await?;

    let res = client.remote_generate().await;
    compare_status_errors(res, Status::unauthenticated("No session key for this user"))?;

    Ok(())
}
