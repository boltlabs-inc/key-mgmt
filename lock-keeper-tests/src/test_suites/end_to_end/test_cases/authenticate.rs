use colored::Colorize;
use lock_keeper::types::{
    audit_event::EventStatus, database::user::AccountName, operations::ClientAction,
};
use lock_keeper_client::{client::Password, Config, LockKeeperClientError};
use std::str::FromStr;

use crate::{
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{authenticate, check_audit_events, compare_errors},
        test_cases::{init_test_state, TestState},
    },
    utils::{tagged, TestResult},
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running authenticate tests".cyan());

    let result = run_parallel!(
        config.clone(),
        multiple_sessions_from_same_client_allowed(config.client_config.clone()),
        cannot_authenticate_with_wrong_password(config.client_config.clone()),
        authenticate_before_register_fails(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn multiple_sessions_from_same_client_allowed(config: Config) -> Result<()> {
    let state = init_test_state(config).await?;

    let _first_login = authenticate(&state).await?;
    let _second_login = authenticate(&state).await?;
    check_audit_events(&state, EventStatus::Successful, ClientAction::Authenticate).await?;

    Ok(())
}

async fn cannot_authenticate_with_wrong_password(config: Config) -> Result<()> {
    let state = init_test_state(config.clone()).await?;
    let wrong_password = Password::from_str(tagged("wrong_password").as_str())?;

    let fake_state = TestState {
        account_name: state.account_name.clone(),
        password: wrong_password,
        config,
    };
    let login = authenticate(&fake_state).await;
    compare_errors(login, LockKeeperClientError::InvalidLogin);
    check_audit_events(&state, EventStatus::Failed, ClientAction::Authenticate).await?;

    Ok(())
}

async fn authenticate_before_register_fails(config: Config) -> Result<()> {
    let account_name = AccountName::from_str(tagged("user").as_str())?;
    let password = Password::from_str(tagged("password").as_str())?;

    let fake_state = TestState {
        account_name,
        password,
        config,
    };
    let login = authenticate(&fake_state).await;
    compare_errors(login, LockKeeperClientError::InvalidAccount);

    Ok(())
}
