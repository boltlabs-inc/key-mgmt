use crate::opaque_storage::{create_or_retrieve_server_key_opaque, retrieve_opaque};
use crate::{
    abort, proceed, protocol,
    protocol::authenticate,
    server::{config::Service, Config},
    timeout::WithTimeout,
};
use anyhow::Context;
use opaque_ke::{ServerLogin, ServerLoginStartParameters};
use rand::rngs::StdRng;
use transport::server::{Chan, SessionKey};

pub struct Authenticate;

impl Authenticate {
    pub async fn run(
        &self,
        rng: &mut StdRng,
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

        let (credential_request, user_id) = auth_start.into_parts();
        let server_registration = match retrieve_opaque(service, &user_id) {
            Ok(server_registration) => server_registration,
            Err(_) => abort!(in chan return authenticate::Error::UserIdDoesNotExist),
        };
        let server_login_start_result = match ServerLogin::start(
            rng,
            &server_setup,
            Some(server_registration),
            credential_request,
            user_id.as_bytes(),
            ServerLoginStartParameters::default(),
        ) {
            Ok(server_login_start_result) => server_login_start_result,
            Err(_) => abort!(in chan return authenticate::Error::ServerError),
        };

        proceed!(in chan);

        let chan = chan
            .send(server_login_start_result.message)
            .await
            .context("Couldn't respond with AuthStartReceived")?;

        let (auth_finish, chan) = chan
            .recv()
            .with_timeout(service.message_timeout)
            .await
            .context("Did not receive AuthFinish")??;

        match server_login_start_result.state.finish(auth_finish) {
            Ok(_) => {
                proceed!(in chan);
                chan.close();
                Ok(())
            }
            Err(_) => abort!(in chan return authenticate::Error::CouldNotAuthenticate),
        }
    }
}
