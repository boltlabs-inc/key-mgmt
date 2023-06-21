use std::time::{Duration, SystemTime};

use crate::{cli_command::CliCommand, state::State};
use anyhow::Error;
use async_trait::async_trait;
use lock_keeper::crypto::SignableBytes;
use lock_keeper_client::LockKeeperClient;

#[derive(Debug)]
pub struct RemoteSign {
    name: String,
    data: String,
}

#[async_trait]
impl CliCommand for RemoteSign {
    async fn execute(self: Box<Self>, state: &mut State) -> Result<Duration, Error> {
        let credentials = state.get_credentials()?;
        // Get key_id from storage
        let entry = state.get_key_id(&self.name)?;

        // Authenticate user to the key server
        let lock_keeper_client = LockKeeperClient::authenticated_client(
            &credentials.account_name,
            &credentials.password,
            &state.config,
        )
        .await
        .result?;

        let bytes = SignableBytes(self.data.into_bytes());

        let now = SystemTime::now();
        // If successful, proceed to generate a secret with the established session
        let signature = lock_keeper_client
            .remote_sign_bytes(entry.key_id.clone(), bytes)
            .await
            .result?;
        let elapsed = now.elapsed()?;

        println!("Signature: {}", hex::encode(signature.to_der()));
        Ok(elapsed)
    }

    fn parse_command_args(slice: &[&str]) -> Option<Self> {
        match slice {
            // All arguments after the key name are joined by spaces to form the text to be signed
            [key_name, string_to_sign @ ..] => Some(RemoteSign {
                name: key_name.to_string(),
                data: string_to_sign.join(" "),
            }),
            _ => None,
        }
    }

    fn format() -> &'static str {
        "remote-sign [key_name] [string_to_sign]"
    }

    fn aliases() -> Vec<&'static str> {
        vec!["remote-sign", "sign", "rs"]
    }

    fn description() -> &'static str {
        "Remotely sign a string with the specified key."
    }
}
