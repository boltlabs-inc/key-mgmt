use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::authenticate::{client, server},
    user::UserId,
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    CredentialResponse,
};
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Channel, Status};

use super::Password;

pub(crate) async fn handle<T: CryptoRng + RngCore>(
    client: &mut DamsRpcClient<Channel>,
    rng: &mut T,
    user_id: &UserId,
    password: &Password,
) -> Result<[u8; 64], Status> {
    // Create channel to send messages to server after connection is established via
    // RPC
    let (tx, rx) = mpsc::channel(2);
    let stream = ReceiverStream::new(rx);

    // Server returns its own channel that is uses to send responses
    let server_response = client.authenticate(stream).await?.into_inner();

    let mut channel = ClientChannel::create(tx, server_response);

    let client_login_start_result =
        ClientLogin::<OpaqueCipherSuite>::start(rng, password.as_bytes())
            .map_err(|_| Status::aborted("LoginStartFailed"))?;

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

async fn authenticate_start(
    channel: &mut ClientChannel,
    client_login_start_result: &ClientLoginStartResult<OpaqueCipherSuite>,
    user_id: &UserId,
) -> Result<server::AuthenticateStart, Status> {
    // Send start message to server
    let client_authenticate_start_message =
        dams::serialize_to_bytes(&client_login_start_result.message)?;

    let reply = client::AuthenticateStart {
        message: client_authenticate_start_message,
        user_id: user_id.as_bytes().to_vec(),
    };

    channel.send(reply).await?;

    channel.receive().await
}

async fn authenticate_finish(
    channel: &mut ClientChannel,
    user_id: &UserId,
    password: &Password,
    client_start_result: ClientLoginStartResult<OpaqueCipherSuite>,
    server_start_result: server::AuthenticateStart,
) -> Result<ClientLoginFinishResult<OpaqueCipherSuite>, Status> {
    let credential_response: CredentialResponse<OpaqueCipherSuite> =
        dams::deserialize_from_bytes(&server_start_result.message)?;

    let client_login_finish_result = client_start_result
        .state
        .finish(
            password.as_bytes(),
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| Status::unauthenticated("Authentication failed"))?;

    let client_login_finish_message =
        dams::serialize_to_bytes(&client_login_finish_result.message)?;

    let reply = client::AuthenticateFinish {
        message: client_login_finish_message,
        user_id: user_id.as_bytes().to_vec(),
    };

    channel.send(reply).await?;

    let server_finish: server::AuthenticateFinish = channel.receive().await?;

    if server_finish.success {
        Ok(client_login_finish_result)
    } else {
        Err(Status::internal("Server returned failure"))
    }
}
