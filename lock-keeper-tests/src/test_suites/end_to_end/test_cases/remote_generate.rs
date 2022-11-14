use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::Config;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{check_audit_events, remote_generate},
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
    )?;

    Ok(result)
}

async fn remote_generate_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let remote_gen_res = remote_generate(&state).await;
    assert!(remote_gen_res.is_ok());

    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::RemoteGenerate,
    )
    .await?;

    Ok(())
}
