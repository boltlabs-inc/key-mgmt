use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;
use rand::Rng;

#[derive(Debug)]
pub struct Import {
    name: Option<String>,
}

#[async_trait]
impl CliCommand for Import {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await?;

        let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
        let key_id = lock_keeper_client
            .import_signing_key(random_bytes)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to import signing key. Error: {:?}", e))?;

        let stored = state.store_entry(self.name, key_id)?;
        println!("Stored: {stored}");
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(Import {
                name: Some(name.to_string()),
            }),
            [] => Some(Import { name: None }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "import [key_name (optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["import", "i"]
    }

    fn description() -> &'static str {
        "Import a randomly generated signing key to the server.
             If you provide a name, the key can be referenced by that name.
             If you don't provide a name, the key can be referenced by the
             number printed to the screen after generation."
    }
}
