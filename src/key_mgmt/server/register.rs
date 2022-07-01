use crate::{
    client::key_mgmt::RegisterStartReceived,
    protocol,
    server::{config::Service, Config},
    timeout::WithTimeout,
};
use anyhow::Context;
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

pub struct Register;

impl Register {
    pub async fn run(
        &self,
        _rng: StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        service: &Service,
        _session_key: SessionKey,
        chan: Chan<protocol::Register>,
    ) -> Result<(), anyhow::Error> {
        let (_register_start, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterStart")??;

        let chan = chan
            .send(RegisterStartReceived {})
            .await
            .context("Couldn't respond with SecretInfo")?;

        let (_register_finish, _chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterFinish")??;

        Ok(())
    }
}
