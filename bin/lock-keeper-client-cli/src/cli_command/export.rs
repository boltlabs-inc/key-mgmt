use crate::{
    cli_command::CliCommand,
    state::State,
    storage::{DataType, Entry},
};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;
use tracing::info;

#[derive(Debug)]
pub struct Export {
    name: String,
}

#[async_trait]
impl CliCommand for Export {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<(), Error> {
        info!("Exporting {}", self.name);

        let credentials = state.get_credentials()?;

        // Authenticate user to the key server.
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        // Get key_id from storage
        let entry = state.get_key_id(&self.name)?;

        let export = lock_keeper_client
            .export_signing_key(&entry.key_id)
            .await
            .result
            .map_err(|e| anyhow::anyhow!("Failed to export signing key. Error: {:?}", e))?;

        println!("Retrieved: {}", self.name);
        println!("{:?}", export);

        let stored = state.store_entry(
            Some(self.name),
            Entry::new(entry.key_id.clone(), DataType::Export(export)),
        )?;
        println!("Updated Key: {stored}");
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(Export {
                name: name.to_string(),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "export [key_name]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["export", "e"]
    }

    fn description() -> &'static str
    where
        Self: Sized,
    {
        "Export a previously generated signing key from the key server
             and update local storage. By default the signing key is not
             removed from the server after exporting. This operation will
             fail if called on an arbitrary key."
    }
}
