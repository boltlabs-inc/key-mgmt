use crate::{DamsClient, DamsClientError};
use dams::{
    crypto::{KeyId, Secret, StorageKey},
    types::retrieve_storage_key::{client, server},
    ClientAction,
};
use serde::{Deserialize, Serialize};

mod generate;

#[allow(unused)]
const SECRET_LENGTH: u32 = 32;

#[derive(Debug, Deserialize, Serialize)]
pub struct LocalStorage {
    pub(crate) secret: Secret,
}

impl DamsClient {
    /// Retrieve the [`dams::crypto::Encrypted<StorageKey>`] that belongs to the
    /// user specified by `user_id`
    async fn retrieve_storage_key(&self) -> Result<StorageKey, DamsClientError> {
        // Create channel to send messages to server
        let mut channel =
            Self::create_channel(&mut self.tonic_client(), ClientAction::RetrieveStorageKey)
                .await?;

        // Send UserId to server
        let request = client::Request {
            user_id: self.user_id().clone(),
        };
        channel.send(request).await?;

        // Get encrypted storage key from server
        let response: server::Response = channel.receive().await?;

        // Decrypt storage_key
        let storage_key = response
            .ciphertext
            .decrypt_storage_key(self.export_key.clone(), self.user_id())?;
        Ok(storage_key)
    }

    /// Generate and store an arbitrary secret at the key server
    pub async fn generate_and_store(&self) -> Result<(KeyId, LocalStorage), DamsClientError> {
        let mut client_channel =
            Self::create_channel(&mut self.tonic_client(), ClientAction::Generate).await?;
        self.handle_generate(&mut client_channel).await
    }
}
