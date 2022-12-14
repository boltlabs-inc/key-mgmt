use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Quit {}

#[async_trait]
impl CliCommand for Quit {
    async fn execute(self: Box<Self>, _state: &mut State) -> Result<(), Error> {
        std::process::exit(0)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            // Ensures the user did try passing extra arguments to this command.
            [] => Some(Quit {}),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "quit"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["quit", "q", "exit"]
    }

    fn description() -> &'static str {
        "Quits the application"
    }
}
