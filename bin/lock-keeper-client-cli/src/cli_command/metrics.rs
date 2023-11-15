use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct Metrics;

#[async_trait]
impl CliCommand for Metrics {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        let now = SystemTime::now();
        let result = lock_keeper_client.metrics().await?;
        println!("{result}");
        let elapsed = now.elapsed()?;

        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(Metrics),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "metrics"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["metrics"]
    }

    fn description() -> &'static str {
        "Prints server metrics."
    }
}
