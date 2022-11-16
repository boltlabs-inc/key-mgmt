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
        operations::{check_audit_events, compare_errors, register},
        test_cases::TestState,
    },
    utils::{tagged, TestResult},
    Config as TestConfig,
};

pub async fn run_tests(config: TestConfig) -> Result<Vec<TestResult>> {
    println!("{}", "Running register tests".cyan());

    let result = run_parallel!(
        config.clone(),
        register_same_user_twice(config.client_config.clone()),
    )?;

    Ok(result)
}

async fn register_same_user_twice(config: Config) -> Result<()> {
    let account_name = AccountName::from_str(tagged("user").as_str())?;
    let password = Password::from_str(tagged("password").as_str())?;
    register(&account_name, &password, &config).await?;

    let second_register = register(&account_name, &password, &config).await;
    compare_errors(
        second_register,
        LockKeeperClientError::AccountAlreadyRegistered,
    );
    let state = TestState {
        account_name,
        password,
        config,
    };
    check_audit_events(&state, EventStatus::Failed, ClientAction::Register).await?;

    Ok(())
}
