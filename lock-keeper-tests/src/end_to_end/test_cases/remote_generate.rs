use colored::Colorize;
use lock_keeper::{
    config::client::Config,
    types::{audit_event::EventStatus, operations::ClientAction},
};

use crate::{
    end_to_end::{
        operations::{check_audit_events, remote_generate},
        test_cases::init_test_state,
    },
    run_parallel,
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> anyhow::Result<Vec<TestResult>> {
    println!("{}", "Running remote generate tests".cyan());

    let result = run_parallel!(
        config.clone(),
        remote_generate_works(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn remote_generate_works(config: Config) -> anyhow::Result<()> {
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
