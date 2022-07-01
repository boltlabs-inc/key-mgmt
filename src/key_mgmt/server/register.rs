use crate::config::opaque::OpaqueCipherSuite;
use crate::{
    protocol,
    server::{config::Service, Config},
    timeout::WithTimeout,
};
use anyhow::Context;
use opaque_ke::{ServerRegistration, ServerSetup};
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

pub struct Register;

impl Register {
    pub async fn run(
        &self,
        mut rng: StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        service: &Service,
        _session_key: SessionKey,
        chan: Chan<protocol::Register>,
    ) -> Result<(), anyhow::Error> {
        let server_setup = ServerSetup::<OpaqueCipherSuite>::new(&mut rng);

        let (register_start, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterStart")??;

        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            register_start.request,
            register_start.username.as_bytes(),
        )
        .unwrap();

        let chan = chan
            .send(server_registration_start_result.message)
            .await
            .context("Couldn't respond with SecretInfo")?;

        let (register_finish, _chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterFinish")??;

        let _password_file = ServerRegistration::finish(register_finish);
        // password_file.serialize();

        Ok(())
    }
}
