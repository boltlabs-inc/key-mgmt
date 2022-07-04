use crate::config::opaque::OpaqueCipherSuite;
use crate::opaque_storage::{create_or_retrieve_server_key_opaque, retrieve_opaque};
use crate::{
    abort, proceed, protocol,
    protocol::authenticate,
    server::{config::Service, Config},
    timeout::WithTimeout,
};
use anyhow::Context;
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerRegistration};
use rand::rngs::{OsRng, StdRng};
use transport::server::{Chan, SessionKey};

pub struct Authenticate;

impl Authenticate {
    pub async fn run(
        &self,
        rng: StdRng,
        _client: &reqwest::Client,
        _config: &Config,
        service: &Service,
        _session_key: SessionKey,
        chan: Chan<protocol::Authenticate>,
    ) -> Result<(), anyhow::Error> {
        let server_setup = create_or_retrieve_server_key_opaque(rng, service)
            .context("could not find/create server key")?;

        let (auth_start, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive RegisterStart")??;

        let password_file_serialized = retrieve_opaque(service, auth_start.username.clone());
        if password_file_serialized.is_err() {
            abort!(in chan return authenticate::Error::UsernameDoesNotExist)
        }
        let password_file = ServerRegistration::<OpaqueCipherSuite>::deserialize(
            &password_file_serialized.unwrap(),
        )
        .unwrap();
        let mut rng = OsRng;
        let server_login_start_result = ServerLogin::start(
            &mut rng,
            &server_setup,
            Some(password_file),
            auth_start.request,
            auth_start.username.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        proceed!(in chan);

        let chan = chan
            .send(server_login_start_result.message)
            .await
            .context("Couldn't respond with AuthStartReceived")?;

        let (auth_finish, _chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive AuthFinish")??;

        let _server_login_finish_result =
            server_login_start_result.state.finish(auth_finish).unwrap();

        Ok(())
    }
}
