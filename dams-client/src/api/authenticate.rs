use crate::client::{DamsClient, Password};

use crate::DamsClientError;
use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    types::authenticate::{client, server},
    user::UserId,
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
};
use rand::{CryptoRng, RngCore};

impl DamsClient {
    pub(crate) async fn handle_authentication<T: CryptoRng + RngCore>(
        mut channel: ClientChannel,
        rng: &mut T,
        user_id: &UserId,
        password: &Password,
    ) -> Result<[u8; 64], DamsClientError> {
        let client_login_start_result =
            ClientLogin::<OpaqueCipherSuite>::start(rng, password.as_bytes())?;

        // Handle start step
        let server_start_result =
            authenticate_start(&mut channel, &client_login_start_result, user_id).await?;

        // Handle finish step
        let client_login_finish_result = authenticate_finish(
            &mut channel,
            user_id,
            password,
            client_login_start_result,
            server_start_result,
        )
        .await?;

        Ok(client_login_finish_result.session_key.into())
    }
}

async fn authenticate_start(
    channel: &mut ClientChannel,
    client_login_start_result: &ClientLoginStartResult<OpaqueCipherSuite>,
    user_id: &UserId,
) -> Result<server::AuthenticateStart, DamsClientError> {
    let reply = client::AuthenticateStart {
        credential_request: client_login_start_result.message.clone(),
        user_id: user_id.clone(),
    };

    channel.send(reply).await?;

    Ok(channel.receive().await?)
}

async fn authenticate_finish(
    channel: &mut ClientChannel,
    user_id: &UserId,
    password: &Password,
    client_start_result: ClientLoginStartResult<OpaqueCipherSuite>,
    server_start_result: server::AuthenticateStart,
) -> Result<ClientLoginFinishResult<OpaqueCipherSuite>, DamsClientError> {
    let client_login_finish_result = client_start_result.state.finish(
        password.as_bytes(),
        server_start_result.credential_response,
        ClientLoginFinishParameters::default(),
    )?;

    let reply = client::AuthenticateFinish {
        credential_finalization: client_login_finish_result.message.clone(),
        user_id: user_id.clone(),
    };

    channel.send(reply).await?;

    let server_finish: server::AuthenticateFinish = channel.receive().await?;

    if server_finish.success {
        Ok(client_login_finish_result)
    } else {
        Err(DamsClientError::ServerReturnedFailure)
    }
}
