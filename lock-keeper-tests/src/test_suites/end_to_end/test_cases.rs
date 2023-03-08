use crate::utils::tagged;
use lock_keeper::types::database::account::AccountName;
use lock_keeper_client::{client::Password, Config, LockKeeperClient, LockKeeperClientError};
use std::str::FromStr;

pub mod authenticate;
pub mod check_session;
pub mod export;
pub mod generate;
pub mod import;
pub mod register;
pub mod remote_generate;
pub mod remote_sign;
pub mod retrieve;

pub(crate) const NO_ENTRY_FOUND: &str = "No such entry in table.";
pub(crate) const WRONG_KEY_DATA: &str =
    "Key ID exists but associated user ID or key type were incorrect.";

pub(crate) struct TestState {
    pub(crate) account_name: AccountName,
    pub(crate) password: Password,
    pub(crate) config: Config,
}

pub(crate) async fn init_test_state(config: &Config) -> Result<TestState, LockKeeperClientError> {
    let account_name = AccountName::from(tagged("user").as_str());
    let password = Password::from_str(tagged("password").as_str())?;
    LockKeeperClient::register(&account_name, &password, config)
        .await
        .result?;
    Ok(TestState {
        account_name,
        password,
        config: config.clone(),
    })
}
