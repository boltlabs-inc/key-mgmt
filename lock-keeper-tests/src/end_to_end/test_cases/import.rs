use colored::Colorize;
use lock_keeper::{
    config::client::Config,
    types::{audit_event::EventStatus, operations::ClientAction},
};

use crate::{
    end_to_end::{
        operations::{check_audit_events, import_signing_key},
        test_cases::init_test_state,
    },
    run_parallel,
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> anyhow::Result<Vec<TestResult>> {
    println!("{}", "Running import tests".cyan());

    let result = run_parallel!(config.clone(), import_works(config.client_config.clone()),)?;

    Ok(result)
}

async fn import_works(config: Config) -> anyhow::Result<()> {
    let state = init_test_state(config).await?;

    let import_res = import_signing_key(&state).await;
    assert!(import_res.is_ok());
    check_audit_events(
        &state,
        EventStatus::Successful,
        ClientAction::ImportSigningKey,
    )
    .await?;

    Ok(())
}
