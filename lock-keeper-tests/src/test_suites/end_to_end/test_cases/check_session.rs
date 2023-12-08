use colored::Colorize;
use lock_keeper_client::lock_keeper::rpc::SessionStatus;
use lock_keeper_client::Config;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{operations::authenticate, test_cases::init_test_state},
    utils::TestResult,
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running check session tests".cyan());

    let result = run_parallel!(
        filters,
        check_session_with_valid_session(config.clone()),
        check_session_with_invalid_session(config.clone())
    )?;

    Ok(result)
}

async fn check_session_with_valid_session(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    let res = client.check_session().await;
    assert!(matches!(
        res,
        Ok(SessionStatus {
            is_session_valid: true
        })
    ));

    Ok(())
}

async fn check_session_with_invalid_session(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = client.check_session().await;
    assert!(matches!(
        res,
        Ok(SessionStatus {
            is_session_valid: false
        })
    ));

    Ok(())
}
