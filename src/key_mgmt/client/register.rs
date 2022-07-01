use super::Command;
use anyhow::Context;
use async_trait::async_trait;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};
use rand::rngs::OsRng;

use crate::client::{
    cli::Register,
    key_mgmt::{connect, Config, RegisterStart},
};
use crate::config::opaque::OpaqueCipherSuite;
use crate::offer_abort;
use crate::protocol::Party::Client;

#[async_trait]
impl Command for Register {
    type Output = ();
    async fn run(self, config: self::Config) -> Result<Self::Output, anyhow::Error> {
        let Self {
            username,
            password,
            server: address,
        } = self;

        let mut rng = OsRng;

        // Connect with the server...
        let (_session_key, chan) = connect(&config, &address)
            .await
            .context("Failed to connect to server")?;

        // ...and select the Create session
        let chan = chan
            .choose::<1>()
            .await
            .context("Failed to select create secret session")?;

        let client_registration_start_result =
            ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();

        let chan = chan
            .send(RegisterStart {
                request: client_registration_start_result.message,
                username,
            })
            .await
            .context("Failed to send RegisterStart")?;

        offer_abort!(in chan as Client);

        let (register_start_received, chan) = chan
            .recv()
            .await
            .context("Failed to recv RegisterStartReceived from server")?;

        let client_finish_registration_result = client_registration_start_result
            .state
            .finish(
                &mut rng,
                password.as_bytes(),
                register_start_received,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();

        chan.send(client_finish_registration_result.message)
            .await
            .context("Failed to send RegisterFinish")?
            .close();

        return Ok(());
    }
}
