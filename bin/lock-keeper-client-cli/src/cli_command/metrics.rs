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
        let now = SystemTime::now();
        let result = LockKeeperClient::metrics(&state.config).await?;
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
