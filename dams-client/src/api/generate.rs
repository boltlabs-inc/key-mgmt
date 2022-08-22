use crate::DamsClientError;
use dams::{
    channel::ClientChannel,
    crypto::{KeyId, StorageKey},
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::generate::{client, server},
    user::UserId,
};
use rand::{CryptoRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Channel, Status};

const SECRET_LENGTH: u32 = 32;

#[allow(unused)]
async fn retrieve_storage_key() -> StorageKey {
    todo!()
}

pub(crate) async fn handle<T: CryptoRng + RngCore>(
    client: &mut DamsRpcClient<Channel>,
    rng: &mut T,
    user_id: &UserId,
) -> Result<KeyId, DamsClientError> {
    // Retrieve the storage key
    let storage_key = retrieve_storage_key().await;

    // Create channel to send messages to server
    let (tx, rx) = mpsc::channel(2);
    let stream = ReceiverStream::new(rx);

    // Server returns its own channel that is uses to send responses
    let server_receiver = client.generate(stream).await?.into_inner();

    let mut channel = ClientChannel::create(tx, server_receiver);

    // Generate step: get new KeyId from server
    let key_id = generate(&mut channel, user_id).await?;
    // Store step: encrypt secret and send to server to store
    store(&mut channel, user_id, storage_key, rng, &key_id).await?;
    Ok(key_id)
}

async fn generate(channel: &mut ClientChannel, user_id: &UserId) -> Result<KeyId, DamsClientError> {
    // Send UserId to server
    let generate_message = client::Generate {
        user_id: user_id.clone(),
    };
    channel
        .send(generate_message)
        .await
        .map_err(|e| Status::aborted(e.to_string()))?;

    // Get KeyId from server
    let generate_result: server::Generate = channel.receive().await?;

    Ok(generate_result.key_id)
}

async fn store<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    user_id: &UserId,
    storage_key: StorageKey,
    rng: &mut T,
    key_id: &KeyId,
) -> Result<(), DamsClientError> {
    // Generate and encrypt secret
    let encrypted_secret = storage_key.create_and_encrypt_secret(rng, user_id, key_id);
    // Serialize and send ciphertext
    let response = client::Store {
        ciphertext: encrypted_secret,
        user_id: user_id.clone(),
    };
    channel.send(response).await?;

    // TODO spec#39 (design, implementation): Store ciphertext in client-side
    // storage

    // Await Ok from server
    let result: server::Store = channel.receive().await?;
    if result.success {
        Ok(())
    } else {
        Err(DamsClientError::ServerReturnedFailure)
    }
}
