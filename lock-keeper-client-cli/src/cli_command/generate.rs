use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;

#[derive(Debug)]
pub struct Generate {
    name: Option<String>,
}

impl Generate {
    pub fn new_name(name: &str) -> Self {
        Self {
            name: Some(name.to_string()),
        }
    }

    pub fn new() -> Self {
        Self { name: None }
    }
}

#[async_trait]
impl CliCommand for Generate {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await?
        .into_inner();

        // If successful, proceed to generate a secret with the established session
        let generate_result = lock_keeper_client.generate_and_store().await?.into_inner();

        // Store Key
        let stored = state.store_entry(self.name, generate_result)?;
        println!("Stored: {stored}");
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(Generate::new_name(name)),
            [] => Some(Generate::new()),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "generate [key_name (optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["generate", "gen", "g"]
    }

    fn description() -> &'static str {
        "Generate an arbitrary key. If you provide a name, the key can be
             referenced by that name. If you don't provide a name, the key
             can be referenced by the number printed to the screen after generation."
    }
}
