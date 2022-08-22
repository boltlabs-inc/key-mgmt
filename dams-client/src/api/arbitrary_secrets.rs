use crate::DamsClientError;
use dams::{
    channel::ClientChannel,
    crypto::{KeyId, OpaqueExportKey, StorageKey},
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::retrieve_storage_key::{client, server},
    user::UserId,
};
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Channel, Status};

mod generate;

#[allow(unused)]
const SECRET_LENGTH: u32 = 32;

/// Retrieve the [`Encrypted<StorageKey>`] that belongs to the user specified by
/// `user_id`
async fn retrieve_storage_key(
    client: &mut DamsRpcClient<Channel>,
    export_key: OpaqueExportKey,
    user_id: &UserId,
) -> Result<StorageKey, DamsClientError> {
    // Create channel to send messages to server
    let (tx, rx) = mpsc::channel(2);
    let stream = ReceiverStream::new(rx);

    // Server returns its own channel that is uses to send responses
    let server_receiver = client.retrieve_storage_key(stream).await?.into_inner();

    let mut channel = ClientChannel::create(tx, server_receiver);

    // Send UserId to server
    let request = client::Request {
        user_id: user_id.clone(),
    };
    channel
        .send(request)
        .await
        .map_err(|e| Status::aborted(e.to_string()))?;

    // Get encrypted storage key from server
    let response: server::Response = channel.receive().await?;

    // Decrypt storage_key
    let storage_key = response.ciphertext.decrypt_storage_key(export_key);
    Ok(storage_key)
}

/// Generate and store an arbitrary secret at the key server
pub async fn generate_and_store<T: CryptoRng + RngCore>(
    client: &mut DamsRpcClient<Channel>,
    rng: &mut T,
    user_id: &UserId,
    export_key: OpaqueExportKey,
) -> Result<KeyId, DamsClientError> {
    generate::handle(client, rng, user_id, export_key).await
}
