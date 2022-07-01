use super::Command;
use anyhow::{anyhow, Context};
use async_trait::async_trait;

use crate::client::{
    cli::Register,
    key_mgmt::{connect, Config, RegisterFinish, RegisterStart},
};

#[async_trait]
impl Command for Register {
    type Output = ();
    async fn run(self, config: self::Config) -> Result<Self::Output, anyhow::Error> {
        let Self { server: address } = self;

        // Connect with the server...
        let (_session_key, chan) = connect(&config, &address)
            .await
            .context("Failed to connect to server")?;

        // ...and select the Create session
        let chan = chan
            .choose::<1>()
            .await
            .context("Failed to select create secret session")?;

        let chan = chan
            .send(RegisterStart {})
            .await
            .context("Failed to send RegisterStart")?;

        let (_register_start_received, chan) = chan
            .recv()
            .await
            .context("Failed to recv RegisterStartReceived from server")?;

        let chan = chan
            .send(RegisterFinish {})
            .await
            .context("Failed to send RegisterFinish");

        if chan.is_ok() {
            return Ok(());
        }
        return Err(anyhow!("Didn't receive correct response from server"));
    }
}
