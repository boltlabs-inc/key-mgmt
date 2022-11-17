use crate::{
    cli_command::CliCommand,
    state::{Credentials, State},
};
use async_trait::async_trait;
use lock_keeper::types::database::user::AccountName;
use lock_keeper_client::{client::Password, LockKeeperClient};

#[derive(Debug)]
pub struct Register {
    account_name: AccountName,
    password: Password,
}

#[async_trait]
impl CliCommand for Register {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), anyhow::Error> {
        LockKeeperClient::register(&self.account_name, &self.password, &state.config).await?;

        println!("Logged in to {}", self.account_name);
        state.credentials = Some(Credentials {
            account_name: self.account_name,
            password: self.password,
        });
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [account, password] => Some(Register {
                account_name: account.parse().ok()?,
                password: password.parse().ok()?,
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "register [account_name] [password]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["register", "reg"]
    }

    fn description() -> &'static str {
        "Registers a new account with the given account_name and password"
    }
}
