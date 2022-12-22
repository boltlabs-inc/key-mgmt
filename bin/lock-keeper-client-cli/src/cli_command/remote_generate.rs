use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct RemoteGenerate {
    name: Option<String>,
}

#[async_trait]
impl CliCommand for RemoteGenerate {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        // If successful, proceed to generate a secret with the established session
        let key_id = lock_keeper_client.remote_generate().await.result?.key_id;

        // Store Key Id
        let stored = state.store_entry(self.name, key_id)?;
        println!("Generated Key: {}", stored);
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(RemoteGenerate {
                name: Some(name.to_string()),
            }),
            [] => Some(RemoteGenerate { name: None }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "remote-generate [key_name (optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["remote-generate", "rgen", "rg"]
    }

    fn description() -> &'static str {
        "Generate a new signing key remotely. This key will be generated
             entirely in the server. If you provide a name, the key can be
             referenced by that name. If you don't provide a name, the key
             can be referenced by the number printed to the screen after generation."
    }
}
