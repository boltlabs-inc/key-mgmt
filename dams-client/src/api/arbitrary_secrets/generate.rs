use crate::{client::ClientAction, DamsClient, DamsClientError};
use dams::{
    channel::ClientChannel,
    crypto::{KeyId, OpaqueExportKey, StorageKey},
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::generate::{client, server},
    user::UserId,
};
use rand::rngs::StdRng;
use tonic::transport::Channel;

impl DamsClient {
    pub(crate) async fn handle_generate(
        &self,
        client: &mut DamsRpcClient<Channel>,
        user_id: &UserId,
        export_key: OpaqueExportKey,
    ) -> Result<KeyId, DamsClientError> {
        // Retrieve the storage key
        let storage_key = self
            .retrieve_storage_key(client, export_key, user_id)
            .await?;

        // Create channel to send messages to server
        let mut channel = Self::create_channel(client, ClientAction::Generate).await?;

        // Generate step: get new KeyId from server
        let key_id = generate(&mut channel, user_id).await?;
        // Store step: encrypt secret and send to server to store
        {
            let mut rng = self.rng.lock().await;
            store(&mut channel, user_id, storage_key, &mut rng, &key_id).await?;
        }

        Ok(key_id)
    }
}

async fn generate(channel: &mut ClientChannel, user_id: &UserId) -> Result<KeyId, DamsClientError> {
    // Send UserId to server
    let generate_message = client::Generate {
        user_id: user_id.clone(),
    };
    channel.send(generate_message).await?;

    // Get KeyId from server
    let generate_result: server::Generate = channel.receive().await?;

    Ok(generate_result.key_id)
}

async fn store(
    channel: &mut ClientChannel,
    user_id: &UserId,
    storage_key: StorageKey,
    rng: &mut StdRng,
    key_id: &KeyId,
) -> Result<(), DamsClientError> {
    // Generate and encrypt secret
    let (_, encrypted) = storage_key.create_and_encrypt_secret(rng, user_id, key_id)?;
    // Serialize and send ciphertext
    let response = client::Store {
        ciphertext: encrypted,
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
