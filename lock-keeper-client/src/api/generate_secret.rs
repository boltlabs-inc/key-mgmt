use crate::{
    api::LocalStorage,
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::{KeyId, Secret, StorageKey},
    types::{
        database::account::UserId,
        operations::generate::{client, server},
    },
};
use rand::rngs::StdRng;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug)]
pub struct GenerateResult {
    pub key_id: KeyId,
    pub local_storage: LocalStorage<Secret>,
}

impl LockKeeperClient {
    pub(crate) async fn handle_generate_secret(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        request_id: Uuid,
    ) -> Result<GenerateResult, LockKeeperClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key(request_id).await?;

        // Generate step: get new KeyId from server
        let key_id = channel.receive::<server::Generate>().await?.key_id;
        // Store step: encrypt secret and send to server to store
        let wrapped_secret = generate_and_store(
            &mut channel,
            self.user_id(),
            storage_key,
            self.rng.clone(),
            &key_id,
        )
        .await?;

        Ok(GenerateResult {
            key_id,
            local_storage: wrapped_secret,
        })
    }
}

async fn generate_and_store(
    channel: &mut Channel<Authenticated<StdRng>>,
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
