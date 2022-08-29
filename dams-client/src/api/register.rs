use crate::{
    client::{DamsClient, Password},
    DamsClientError,
};
use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    types::register::{client, server},
    user::UserId,
};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
};
use rand::{CryptoRng, RngCore};
use tonic::Response;

impl DamsClient {
    pub(crate) async fn handle_registration<T: CryptoRng + RngCore>(
        mut channel: ClientChannel,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
    ) -> Result<Response<server::RegisterFinish>, DamsClientError> {
        // Handle start step
        let client_start_result = register_start(&mut channel, rng, user_id, password).await?;

        // Handle finish step
        let server_finish_result =
            register_finish(&mut channel, rng, user_id, password, client_start_result).await?;

        Ok(Response::new(server_finish_result))
    }
}

async fn register_start<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    user_id: &UserId,
    password: &Password,
) -> Result<ClientRegistrationStartResult<OpaqueCipherSuite>, DamsClientError> {
    let client_registration_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())?;

    let response = client::RegisterStart {
        registration_request: client_registration_start_result.message.clone(),
        user_id: user_id.clone(),
    };

    channel.send(response).await?;

    Ok(client_registration_start_result)
}

async fn register_finish<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    user_id: &UserId,
    password: &Password,
    client_start_result: ClientRegistrationStartResult<OpaqueCipherSuite>,
) -> Result<server::RegisterFinish, DamsClientError> {
    let server_start_result: server::RegisterStart = channel.receive().await?;

    let client_finish_registration_result = client_start_result.state.finish(
        rng,
        password.as_bytes(),
        server_start_result.registration_response,
        ClientRegistrationFinishParameters::default(),
    )?;

    let response = client::RegisterFinish {
        registration_upload: client_finish_registration_result.message,
        user_id: user_id.clone(),
    };
    channel.send(response).await?;

    let result = channel.receive().await?;

    Ok(result)
}
