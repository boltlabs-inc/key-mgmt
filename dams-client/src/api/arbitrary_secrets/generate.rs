use crate::{DamsClient, DamsClientError};
use dams::{
    channel::ClientChannel,
    crypto::{KeyId, OpaqueExportKey, Secret, StorageKey},
    types::generate::{client, server},
    user::UserId,
};
use rand::rngs::StdRng;

impl DamsClient {
    pub(crate) async fn handle_generate(
        &mut self,
        channel: &mut ClientChannel,
        user_id: &UserId,
        export_key: OpaqueExportKey,
    ) -> Result<(KeyId, Secret), DamsClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key(export_key, user_id).await?;

        // Generate step: get new KeyId from server
        let key_id = generate(channel, user_id).await?;
        // Store step: encrypt secret and send to server to store
        let secret = {
            let mut rng = self.rng.lock().await;
            store(channel, user_id, storage_key, &mut rng, &key_id).await?
        };

        Ok((key_id, secret))
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
) -> Result<Secret, DamsClientError> {
    // Generate and encrypt secret
    let (secret, encrypted) = storage_key.create_and_encrypt_secret(rng, user_id, key_id)?;
    // Serialize and send ciphertext
    let response = client::Store {
        ciphertext: encrypted.clone(),
        user_id: user_id.clone(),
    };
    channel.send(response).await?;

    // TODO spec#39 (design, implementation): Store ciphertext in client-side
    // storage

    // Await Ok from server
    let result: server::Store = channel.receive().await?;
    if result.success {
        Ok(secret)
    } else {
        Err(DamsClientError::ServerReturnedFailure)
    }
}