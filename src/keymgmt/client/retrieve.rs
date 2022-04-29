use super::Command;
use anyhow::{anyhow, Context};
use async_trait::async_trait;

use crate::client::{
    cli::Retrieve,
    keymgmt::{connect, Config, SecretRetrieveRequest},
};

#[async_trait]
impl Command for Retrieve {
    type Output = ();
    async fn run(self, config: self::Config) -> Result<Self::Output, anyhow::Error> {
        let Self { server: address } = self;

        // Connect with the server...
        let (_session_key, chan) = connect(&config, &address)
            .await
            .context("Failed to connect to server")?;

        // ...and select the retrieve session
        let chan = chan
            .choose::<1>()
            .await
            .context("Failed to select retrieve secret session")?;

        let chan = chan
            .send(SecretRetrieveRequest {})
            .await
            .context("Failed to send SecretRetrieveRequest")?;

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
