use anyhow::{anyhow, Context};
use dams::{
    abort,
    config::{
        opaque::OpaqueCipherSuite,
        server::{Config, Service},
    },
    opaque_storage::{create_or_retrieve_server_key_opaque, retrieve_opaque, store_opaque},
    proceed, protocol,
    protocol::register,
    timeout::WithTimeout,
};
use opaque_ke::ServerRegistration;
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

pub struct Register;

impl Register {
    pub async fn run(
        &self,
        rng: &mut StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        service: &Service,
        _session_key: SessionKey,
        chan: Chan<protocol::Register>,
    ) -> Result<(), anyhow::Error> {
        let server_setup = create_or_retrieve_server_key_opaque(rng, service)
            .context("could not find/create server key")?;

        let (register_start, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterStart")??;
        let (registration_request_message, user_id) = register_start.into_parts();

        if retrieve_opaque(service, &user_id).is_ok() {
            abort!(in chan return register::Error::UserIdAlreadyExists);
        }
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            registration_request_message,
            user_id.as_bytes(),
        )
        .map_err(|_| anyhow!("could not start server registration"))?;

        proceed!(in chan);

        let chan = chan
            .send(server_registration_start_result.message)
            .await
            .context("Couldn't respond with RegisterStartReceived")?;

        let (register_finish, _chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterFinish")??;

        let server_registration = ServerRegistration::<OpaqueCipherSuite>::finish(register_finish);
        store_opaque(service, &user_id, &server_registration)?;

        Ok(())
    }
}
