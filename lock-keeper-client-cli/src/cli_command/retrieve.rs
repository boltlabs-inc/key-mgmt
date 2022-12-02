use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper::types::operations::retrieve_secret::RetrieveContext;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct Retrieve {
    name: String,
}

#[async_trait]
impl CliCommand for Retrieve {
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

        let entry = state.get_key_id(&self.name)?;
        // Retrieve results for specified key.
        let retrieve_result = lock_keeper_client
            .retrieve_secret(&entry.key_id, RetrieveContext::LocalOnly)
            .await?
            .into_inner();

        println!("Retrieved: {}", self.name);
        println!("{retrieve_result:?}");

        let stored = state.store_entry(Some(self.name), (entry.key_id.clone(), retrieve_result))?;

        println!("Updated: {stored}");
        Ok(())
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(Retrieve {
                name: name.to_string(),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "retrieve [key_name]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["retrieve", "r"]
    }

    fn description() -> &'static str {
        "Retrieve a previously generated arbitrary key from the server
             and update local storage. This command will fail if the key is a
             signing key."
    }
}
