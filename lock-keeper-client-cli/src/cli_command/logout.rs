use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Logout {}

#[async_trait]
impl CliCommand for Logout {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        state.credentials = None;
        Ok(())
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
