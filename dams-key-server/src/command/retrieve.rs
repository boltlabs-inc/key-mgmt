use anyhow::Context;
use dams::{
    config::server::{Config, Service},
    protocol,
    timeout::WithTimeout,
};
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

#[allow(unused)]
pub struct Retrieve;

#[allow(unused)]
impl Retrieve {
    pub async fn run(
        &self,
        _rng: StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        service: &Service,
        _session_key: SessionKey,
        chan: Chan<protocol::Retrieve>,
    ) -> Result<(), anyhow::Error> {
        let (_create_secret_request, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive create secret request")??;

        chan.send(protocol::SecretInfo {})
            .await
            .context("Couldn't respond with SecretInfo")?
            .close();
        Ok(())
    }
}
