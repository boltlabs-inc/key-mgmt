use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Print {
    name: String,
}

#[async_trait]
impl CliCommand for Print {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        let _credentials = state.get_credentials()?;

        // Get key_id from storage
        let entry = state.get_key_id(&self.name)?;

        println!("name: {}", self.name);
        println!("{entry}");
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(Print {
                name: name.to_string(),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "print [key_name]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["print", "p"]
    }

    fn description() -> &'static str {
        "Prints all stored information about the given key."
    }
}
