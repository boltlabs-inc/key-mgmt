use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct Health;

#[async_trait]
impl CliCommand for Health {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let now = SystemTime::now();
        let result = LockKeeperClient::health(&state.config).await;
        let elapsed = now.elapsed()?;

        match result {
            Ok(()) => println!("Health check passed"),
            Err(e) => {
                println!("Health check failed");
                dbg!(e);
            }
        }

        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(Health),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "health"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["health"]
    }

    fn description() -> &'static str {
        "Calls the health check operation and prints debug information if an error is returned."
    }
}
