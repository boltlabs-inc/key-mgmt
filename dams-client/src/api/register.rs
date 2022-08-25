use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::register::{client, server},
    user::UserId,
};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
};
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Channel, Response, Status};

use super::Password;

pub(crate) async fn handle<T: CryptoRng + RngCore>(
    client: &mut DamsRpcClient<Channel>,
    rng: &mut T,
    user_id: &UserId,
    password: &Password,
) -> Result<Response<server::RegisterFinish>, Status> {
    // Create channel to send messages to server
    let (tx, rx) = mpsc::channel(2);
    let stream = ReceiverStream::new(rx);

    // Server returns its own channel that is uses to send responses
    let server_receiver = client.register(stream).await?.into_inner();

    let mut channel = ClientChannel::create(tx, server_receiver);

    // Handle start step
    let client_start_result = register_start(&mut channel, rng, user_id, password).await?;

    // Handle finish step
    let server_finish_result =
        register_finish(&mut channel, rng, user_id, password, client_start_result).await?;

    Ok(Response::new(server_finish_result))
}

async fn register_start<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    user_id: &UserId,
    password: &Password,
) -> Result<ClientRegistrationStartResult<OpaqueCipherSuite>, Status> {
    let client_registration_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())
            .map_err(|_| Status::aborted("RegistrationStart failed"))?;

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
) -> Result<server::RegisterFinish, Status> {
    let server_start_result: server::RegisterStart = channel.receive().await?;

    let client_finish_registration_result = client_start_result
        .state
        .finish(
            rng,
            password.as_bytes(),
            server_start_result.registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| Status::aborted("RegistrationFinish failed"))?;

    let response = client::RegisterFinish {
        registration_upload: client_finish_registration_result.message,
        user_id: user_id.clone(),
    };
    channel.send(response).await?;

    let result = channel.receive().await?;

    Ok(result)
}
