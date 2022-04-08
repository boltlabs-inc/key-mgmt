use crate::protocol;
use crate::server::config::Service;
use crate::server::Config;
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

pub struct Create;

impl Create {
    pub async fn run(
        &self,
        _rng: StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        _service: &Service,
        _session_key: SessionKey,
        _chan: Chan<protocol::Create>,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
