use crate::{end_to_end::operations::register, utils::tagged};
use lock_keeper::{config::client::Config, types::database::user::AccountName};
use lock_keeper_client::{client::Password, LockKeeperClientError};
use std::str::FromStr;

pub mod authenticate;
pub mod export;
pub mod generate;
pub mod import;
pub mod register;
pub mod remote_generate;
pub mod remote_sign;
pub mod retrieve;

pub(crate) struct TestState {
    pub(crate) account_name: AccountName,
    pub(crate) password: Password,
    pub(crate) config: Config,
}

pub(crate) async fn init_test_state(config: Config) -> Result<TestState, LockKeeperClientError> {
    let account_name = AccountName::from_str(tagged("user").as_str())?;
    let password = Password::from_str(tagged("password").as_str())?;
    register(&account_name, &password, &config).await?;
    Ok(TestState {
        account_name,
        password,
        config,
    })
}
