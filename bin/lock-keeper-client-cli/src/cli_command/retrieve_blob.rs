use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct RetrieveBlob {
    name: String,
}

#[async_trait]
impl CliCommand for RetrieveBlob {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let credentials = state.get_credentials()?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        let entry = state.get_key_id(&self.name)?;

        let now = SystemTime::now();
        // Retrieve results for specified key.
        let retrieve_result = lock_keeper_client
            .retrieve_server_encrypted_blob(&entry.key_id)
            .await
            .result?;
        let elapsed = now.elapsed()?;

        println!("Retrieved: {}", self.name);
        println!("{retrieve_result:?}");

        let stored = state.store_entry(Some(self.name), (entry.key_id.clone(), retrieve_result))?;

        println!("Updated: {stored}");
        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [name] => Some(RetrieveBlob {
                name: name.to_string(),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "retrieve-blob [key_name]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["retrieve-blob", "rb"]
    }

    fn description() -> &'static str {
        "Retrieve a previously stored blob."
    }
}
