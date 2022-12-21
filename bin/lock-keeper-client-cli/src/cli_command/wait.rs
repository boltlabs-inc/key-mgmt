use std::time::Duration;

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Wait {
    duration: Duration,
}

#[async_trait]
impl CliCommand for Wait {
    async fn execute(self: Box<Self>, _state: &mut State) -> Result<Duration, Error> {
        let humantime: humantime::Duration = self.duration.into();
        println!("Waiting {humantime}");
        tokio::time::sleep(self.duration).await;

        // Return zero duration since this command doesn't call the client.
        Ok(Duration::ZERO)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [humantime_string] => Some(Wait {
                duration: humantime_string.parse::<humantime::Duration>().ok()?.into(),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "wait [humantime duration]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["wait"]
    }

    fn description() -> &'static str {
        "Waits the specified duration before continuing. Useful in scripts."
    }
}
