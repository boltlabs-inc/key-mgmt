use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct StoreBlob {
    blob: String,
    name: Option<String>,
}

#[async_trait]
impl CliCommand for StoreBlob {
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

        let now = SystemTime::now();
        // If successful, proceed to generate a secret with the established session
        let key_id = lock_keeper_client
            .store_server_encrypted_blob(self.blob.into_bytes())
            .await
            .result?;
        let elapsed = now.elapsed()?;

        // Store Key Id
        let stored = state.store_entry(self.name, key_id)?;
        println!("Stored blob with id: {stored}");
        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            [blob, name] => Some(StoreBlob {
                blob: blob.to_string(),
                name: Some(name.to_string()),
            }),
            [blob] => Some(StoreBlob {
                blob: blob.to_string(),
                name: None,
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "store-blob [key_name (optional)]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["store-blob", "blob", "sb"]
    }

    fn description() -> &'static str {
        "Store an arbitrary blob of bytes."
    }
}
