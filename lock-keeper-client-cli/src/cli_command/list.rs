use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct List {}

#[async_trait]
impl CliCommand for List {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        let lock_keeper_client = state.get_client()?;
        state.storage.list(lock_keeper_client.account_name())?;
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(List {}),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "list"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["list", "ls"]
    }

    fn description() -> &'static str {
        "Prints stored information about every key associated with the
             current account."
    }
}
