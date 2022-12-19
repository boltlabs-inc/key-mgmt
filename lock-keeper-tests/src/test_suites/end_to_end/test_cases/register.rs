use colored::Colorize;
use lock_keeper::types::{
    audit_event::EventStatus, database::user::AccountName, operations::ClientAction,
};
use lock_keeper_client::{client::Password, Config, LockKeeperClient};
use std::str::FromStr;
use tonic::Status;

use crate::{
    config::TestFilters,
    error::Result,
    run_parallel,
    test_suites::end_to_end::{
        operations::{check_audit_events, compare_status_errors},
        test_cases::TestState,
    },
    utils::{tagged, TestResult},
};

pub async fn run_tests(config: &Config, filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running register tests".cyan());

    let result = run_parallel!(filters, register_same_user_twice_fails(config.clone()),)?;

    Ok(result)
}

async fn register_same_user_twice_fails(config: Config) -> Result<()> {
    let account_name = AccountName::from_str(tagged("user").as_str())?;
    let password = Password::from_str(tagged("password").as_str())?;
    LockKeeperClient::register(&account_name, &password, &config).await?;

    let second_register = LockKeeperClient::register(&account_name, &password, &config).await;
    compare_status_errors(
        second_register,
        Status::invalid_argument("Account already registered."),
    )?;
    let state = TestState {
        account_name,
        password,
        config,
    };
    check_audit_events(&state, EventStatus::Failed, ClientAction::Register).await?;

    Ok(())
}
