use crate::{
    cli_command::CliCommand,
    state::{Credentials, State},
};
use async_trait::async_trait;
use lock_keeper::types::database::user::AccountName;
use lock_keeper_client::{client::Password, LockKeeperClient};

#[derive(Debug)]
pub struct Authenticate {
    account_name: AccountName,
    password: Password,
}

#[async_trait]
impl CliCommand for Authenticate {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), anyhow::Error> {
        LockKeeperClient::authenticated_client(&self.account_name, &self.password, &state.config)
            .await?;

        println!("Logged in to {}", self.account_name);
        state.credentials = Some(Credentials {
            account_name: self.account_name,
            password: self.password,
        });
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [account, password] => Some(Self {
                account_name: account.parse().ok()?,
                password: password.parse().ok()?,
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "authenticate [account_name] [password]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["authenticate", "auth", "a", "login"]
    }

    fn description() -> &'static str {
        "Authenticates to a previously registered account. Authentication is required for most commands."
    }
}
