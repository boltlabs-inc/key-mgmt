use colored::Colorize;
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

    let res = client.check_session().await?;
    let key_mgmt_version = String::from("develop");
    let build_date = String::from("develop");
    assert!(res.is_session_valid);
    assert_eq!(res.key_mgmt_version, key_mgmt_version);
    assert_eq!(res.build_date, build_date);

    Ok(())
}

async fn check_session_with_invalid_session(config: Config) -> Result<()> {
    let state = init_test_state(&config).await?;
    let client = authenticate(&state).await.result?;

    client.logout().await.result?;

    let res = client.check_session().await?;
    let key_mgmt_version = String::from("develop");
    let build_date = String::from("develop");
    assert!(!res.is_session_valid);
    assert_eq!(res.key_mgmt_version, key_mgmt_version);
    assert_eq!(res.build_date, build_date);

    Ok(())
}
