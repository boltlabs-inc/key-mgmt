use colored::Colorize;
use lock_keeper::types::{audit_event::EventStatus, operations::ClientAction};
use lock_keeper_client::Config;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{check_audit_events, generate},
        test_cases::init_test_state,
    },
    utils::TestResult,
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running generate tests".cyan());

    let result = run_parallel!(config.clone(), generate_works(config.client_config.clone()),)?;

    Ok(result)
}

async fn generate_works(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let _ = generate(&state).await?;
    check_audit_events(&state, EventStatus::Successful, ClientAction::Generate).await?;

    Ok(())
}
