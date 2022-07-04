use super::Command;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use opaque_ke::{ClientLogin, ClientLoginFinishParameters};
use rand::rngs::OsRng;

use crate::client::{
    cli::Authenticate,
    key_mgmt::{connect, AuthStart, Config},
};
use crate::config::opaque::OpaqueCipherSuite;
use crate::offer_abort;
use crate::protocol::Party::Client;

#[async_trait]
impl Command for Authenticate {
    type Output = [u8; 64];
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
            .choose::<3>()
            .await
            .context("Failed to select create secret session")?;

        let client_login_start_result =
            ClientLogin::<OpaqueCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();

        let chan = chan
            .send(AuthStart {
                request: client_login_start_result.message,
                username,
            })
            .await
            .context("Failed to send AuthStart")?;

        offer_abort!(in chan as Client);

        let (auth_start_received, chan) = chan
            .recv()
            .await
            .context("Failed to recv AuthStartReceived from server")?;

        let result = client_login_start_result.state.finish(
            password.as_bytes(),
            auth_start_received,
            ClientLoginFinishParameters::default(),
        );

        if result.is_err() {
            // Client-detected login failure
            return Err(anyhow!("not authenticated"));
        }
        let client_login_finish_result = result.unwrap();

        chan.send(client_login_finish_result.message)
            .await
            .context("Failed to send AuthFinish")?
            .close();

        return Ok(<[u8; 64]>::from(client_login_finish_result.session_key));
    }
}
