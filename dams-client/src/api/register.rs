use crate::{
    client::{DamsClient, Password},
    DamsClientError,
};
use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    types::register::{client, server},
    user::AccountName,
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
        account_name: &AccountName,
        password: &Password,
    ) -> Result<Response<server::RegisterFinish>, DamsClientError> {
        // Handle start step
        let client_start_result = register_start(&mut channel, rng, account_name, password).await?;

        // Handle finish step
        let server_finish_result = register_finish(
            &mut channel,
            rng,
            account_name,
            password,
            client_start_result,
        )
        .await?;

        Ok(Response::new(server_finish_result))
    }
}

async fn register_start<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    account_name: &AccountName,
    password: &Password,
) -> Result<ClientRegistrationStartResult<OpaqueCipherSuite>, DamsClientError> {
    let client_registration_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())?;

    let response = client::RegisterStart {
        registration_request: client_registration_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(response).await?;

    Ok(client_registration_start_result)
}

async fn register_finish<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    account_name: &AccountName,
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
        account_name: account_name.clone(),
    };
    channel.send(response).await?;

    let result = channel.receive().await?;

    Ok(result)
}
