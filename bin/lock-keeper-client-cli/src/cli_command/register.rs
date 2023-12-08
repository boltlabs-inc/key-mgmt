use std::time::{Duration, SystemTime};

use crate::{
    cli_command::CliCommand,
    state::{Credentials, State},
};
use async_trait::async_trait;
use lock_keeper_client::lock_keeper::types::database::account::AccountName;
use lock_keeper_client::{client::Password, LockKeeperClient};
use rand::{distributions::Alphanumeric, Rng};

#[derive(Debug)]
pub struct Register {
    account_name: AccountName,
    password: Password,
}

#[async_trait]
impl CliCommand for Register {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, anyhow::Error> {
        let password_string = std::str::from_utf8(self.password.as_bytes())?;
        println!(
            "Registering:\naccount_name: {}\npassword: {}",
            &self.account_name, password_string
        );

        let now = SystemTime::now();
        LockKeeperClient::register(&self.account_name, &self.password, &state.config)
            .await
            .result?;
        let elapsed = now.elapsed()?;

        println!("Logged in to {}", self.account_name);
        state.credentials = Some(Credentials {
            account_name: self.account_name,
            password: self.password,
        });
        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [account, password] => Some(Register {
                account_name: account.parse().ok()?,
                password: password.parse().ok()?,
            }),
            [] => {
                let random_part: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(5)
                    .map(char::from)
                    .collect();
                let account_name = format!("user-{random_part}");
                let password = "pass123";

                Some(Register {
                    account_name: account_name.parse().ok()?,
                    password: password.parse().ok()?,
                })
            }
            _ => None,
        }
    }

    fn format() -> &'static str {
        "register [account_name (optional)] [password (optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["register", "reg"]
    }

    fn description() -> &'static str {
        "Registers a new account. Uses given account_name and password if provided,
            or a random username and the password \"pass123\" if not provided."
    }
}
