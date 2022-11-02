use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct GetAuditEvents {}

#[async_trait]
impl CliCommand for GetAuditEvents {
    async fn execute(self: Box<Self>, _state: &mut State) -> Result<(), Error> {
        println!("{:?}: Not implemented", GetAuditEvents {});
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [] => Some(GetAuditEvents {}),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "audit"
    }

    fn aliases() -> Vec<&'static str>
    where
        Self: Sized,
    {
        vec!["audit"]
    }

    fn description() -> &'static str
    where
        Self: Sized,
    {
        "Not implemented."
    }
}
