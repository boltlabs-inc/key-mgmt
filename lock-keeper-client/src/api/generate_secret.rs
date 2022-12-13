use crate::{api::LocalStorage, LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use lock_keeper::{
    crypto::{KeyId, Secret, StorageKey},
    infrastructure::channel::{Authenticated, ClientChannel},
    types::{
        database::user::UserId,
        operations::generate::{client, server},
    },
};
use rand::rngs::StdRng;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct GenerateResult {
    pub key_id: KeyId,
    pub local_storage: LocalStorage<Secret>,
}

impl LockKeeperClient {
    pub(crate) async fn handle_generate_secret(
        &self,
        mut channel: ClientChannel<Authenticated<StdRng>>,
    ) -> Result<LockKeeperResponse<GenerateResult>, LockKeeperClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key().await?;

        // Generate step: get new KeyId from server
        let key_id = get_key_id(&mut channel, self.user_id()).await?;
        // Store step: encrypt secret and send to server to store
        let wrapped_secret = generate_and_store(
            &mut channel,
            self.user_id(),
            storage_key,
            self.rng.clone(),
            &key_id,
        )
        .await?;

        let result = GenerateResult {
            key_id,
            local_storage: wrapped_secret,
        };

        Ok(LockKeeperResponse::from_channel(channel, result))
    }
}

async fn get_key_id(
    channel: &mut ClientChannel<Authenticated<StdRng>>,
    user_id: &UserId,
) -> Result<KeyId, LockKeeperClientError> {
    // Send UserId to server
    let generate_message = client::Generate {
        user_id: user_id.clone(),
    };
    channel.send(generate_message).await?;

    // Get KeyId from server
    let generate_result: server::Generate = channel.receive().await?;

    Ok(generate_result.key_id)
}

async fn generate_and_store(
    channel: &mut ClientChannel<Authenticated<StdRng>>,
    user_id: &UserId,
    storage_key: StorageKey,
    rng: Arc<Mutex<StdRng>>,
    key_id: &KeyId,
) -> Result<LocalStorage<Secret>, LockKeeperClientError> {
    // Generate and encrypt secret
    let (secret, encrypted) = {
        let mut rng = rng.lock().await;
        Secret::create_and_encrypt(&mut *rng, &storage_key, user_id, key_id)?
    };
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
        Ok(LocalStorage { material: secret })
    } else {
        Err(LockKeeperClientError::ServerReturnedFailure)
    }
}
