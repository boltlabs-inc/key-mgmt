use dams::{
    channel::ClientChannel,
    config::opaque::OpaqueCipherSuite,
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::register::{client, server},
    user::UserId,
};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
    RegistrationResponse,
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

    // Send start message to server
    let message = dams::serialize_to_bytes(&client_registration_start_result.message)?;

    let response = client::RegisterStart {
        message,
        user_id: user_id.as_bytes().to_vec(),
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

    let server_register_start_message: RegistrationResponse<OpaqueCipherSuite> =
        dams::deserialize_from_bytes(&server_start_result.message)?;

    let client_finish_registration_result = client_start_result
        .state
        .finish(
            rng,
            password.as_bytes(),
            server_register_start_message,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| Status::aborted("RegistrationFinish failed"))?;

    let client_finish_registration_message =
        dams::serialize_to_bytes(&client_finish_registration_result.message)?;

    let response = client::RegisterFinish {
        message: client_finish_registration_message,
        user_id: user_id.as_bytes().to_vec(),
    };
    channel.send(response).await?;

    let result = channel.receive().await?;

    Ok(result)
}
