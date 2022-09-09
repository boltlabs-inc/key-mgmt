use crate::client::{DamsClient, Password};

use crate::DamsClientError;
use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    crypto::{OpaqueExportKey, OpaqueSessionKey},
    types::authenticate::{client, server},
    user::{AccountName, UserId},
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
};
use rand::{CryptoRng, RngCore};

impl DamsClient {
    pub(crate) async fn handle_authentication<T: CryptoRng + RngCore>(
        mut channel: ClientChannel,
        rng: &mut T,
        account_name: &AccountName,
        password: &Password,
    ) -> Result<(OpaqueSessionKey, OpaqueExportKey, UserId), DamsClientError> {
        let client_login_start_result =
            ClientLogin::<OpaqueCipherSuite>::start(rng, password.as_bytes())?;

        // Handle start step
        let server_start_result =
            authenticate_start(&mut channel, &client_login_start_result, account_name).await?;

        // Handle finish step
        let client_login_finish_result = authenticate_finish(
            &mut channel,
            account_name,
            password,
            client_login_start_result,
            server_start_result,
        )
        .await?;

        let session_key = client_login_finish_result.session_key.into();
        let export_key = client_login_finish_result.export_key.into();

        // Get user id
        let user_id = retrieve_user_id(&mut channel, &session_key).await?;

        Ok((session_key, export_key, user_id))
    }
}

async fn authenticate_start(
    channel: &mut ClientChannel,
    client_login_start_result: &ClientLoginStartResult<OpaqueCipherSuite>,
    account_name: &AccountName,
) -> Result<server::AuthenticateStart, DamsClientError> {
    let reply = client::AuthenticateStart {
        credential_request: client_login_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(reply).await?;

    Ok(channel.receive().await?)
}

async fn authenticate_finish(
    channel: &mut ClientChannel,
    account_name: &AccountName,
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
        account_name: account_name.clone(),
    };

    channel.send(reply).await?;

    let server_finish: server::AuthenticateFinish = channel.receive().await?;

    if server_finish.success {
        Ok(client_login_finish_result)
    } else {
        Err(DamsClientError::ServerReturnedFailure)
    }
}

/// Retrieve the authenticated user ID from the server.
///
/// NB: The unused `_session_key` will have to be passed to receive in order to
/// check authentication.
async fn retrieve_user_id(
    channel: &mut ClientChannel,
    _session_key: &OpaqueSessionKey,
) -> Result<UserId, DamsClientError> {
    let received_id: server::SendUserId = channel.receive().await?;
    Ok(received_id.user_id)
}
