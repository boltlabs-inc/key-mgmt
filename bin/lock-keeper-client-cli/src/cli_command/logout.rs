use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct Logout {}

#[async_trait]
impl CliCommand for Logout {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let remote_logout_result = self.remote_logout(state).await;

        // Clear stored credentials regardless of whether or not remote logout succeeded
        // We need the credentials to log out of the server so we can't clear this until
        // after the remote operation.
        state.credentials = None;

        remote_logout_result
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(Logout {}),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "logout"
    }

    fn aliases() -> Vec<&'static str>
    where
        Self: Sized,
    {
        vec!["logout"]
    }

    fn description() -> &'static str {
        "Log out of currently authenticated account."
    }
}

impl Logout {
    async fn remote_logout(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let credentials = state.get_credentials()?;

        // Authenticate to get a client that we can use to log out
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        let now = SystemTime::now();
        lock_keeper_client.logout().await.result?;
        let elapsed = now.elapsed()?;

        Ok(elapsed)
    }
}
