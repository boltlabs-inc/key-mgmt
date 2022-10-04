use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::{KeyId, Secret, StorageKey},
    types::retrieve_storage_key::{client, server},
    ClientAction, RetrieveContext,
};
use serde::{Deserialize, Serialize};

mod generate;
mod retrieve;

/// Ways of returning a key from the retrieval process based on usage
/// [`RetrieveContext`]
#[derive(Debug, Deserialize, Serialize)]
pub enum RetrieveResult {
    None,
    ArbitraryKey(LocalStorage),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LocalStorage {
    pub(crate) secret: Secret,
}

impl LockKeeperClient {
    /// Retrieve the [`lock_keeper::crypto::Encrypted<StorageKey>`] that belongs
    /// to the user specified by `user_id`
    async fn retrieve_storage_key(&self) -> Result<StorageKey, LockKeeperClientError> {
        // Create channel to send messages to server
        let mut channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::RetrieveStorageKey,
            self.account_name(),
        )
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
    pub async fn generate_and_store(&self) -> Result<(KeyId, LocalStorage), LockKeeperClientError> {
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::Generate,
            self.account_name(),
        )
        .await?;
        self.handle_generate(&mut client_channel).await
    }

    /// Retrieve an arbitrary secret from the key server by [`KeyId`]
    pub async fn retrieve(
        &self,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<RetrieveResult, LockKeeperClientError> {
        let mut client_channel = Self::create_channel(
            &mut self.tonic_client(),
            ClientAction::Retrieve,
            self.account_name(),
        )
        .await?;
        self.handle_retrieve(&mut client_channel, key_id, context)
            .await
    }
}
