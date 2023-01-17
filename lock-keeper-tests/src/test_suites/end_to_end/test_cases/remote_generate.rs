use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::Config;
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, compare_status_errors},
        test_cases::{init_test_state, NO_SESSION},
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
    assert!(remote_gen_res.result.is_ok());

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteGenerateSigningKey,
        request_id,
    )
    .await?;

    Ok(())
}

async fn cannot_remote_generate_after_logout(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = client.remote_generate().await;
    compare_status_errors(res, Status::unauthenticated(NO_SESSION))?;

    Ok(())
}
