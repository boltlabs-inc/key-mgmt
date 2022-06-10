use super::Command;
use anyhow::{anyhow, Context};
use async_trait::async_trait;

use crate::client::{
    cli::Create,
    keymgmt::{connect, Config, CreateSecretRequest},
};

#[async_trait]
impl Command for Create {
    type Output = ();
    async fn run(self, config: self::Config) -> Result<Self::Output, anyhow::Error> {
        let Self { server: address } = self;

        // Connect with the server...
        let (_session_key, chan) = connect(&config, &address)
            .await
            .context("Failed to connect to server")?;

        // ...and select the Create session
        let chan = chan
            .choose::<0>()
            .await
            .context("Failed to select create secret session")?;

        let chan = chan
            .send(CreateSecretRequest {})
            .await
            .context("Failed to send CreateSecretRequest")?;

        let result = chan
            .recv()
            .await
            .context("Failed to recv SecretInfo from server");
        if result.is_ok() {
            return Ok(());
        }
        return Err(anyhow!("Didn't receive correct response from server"));
    }
}
