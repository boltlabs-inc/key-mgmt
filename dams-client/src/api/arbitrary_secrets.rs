use crate::{client::ClientAction, DamsClient, DamsClientError};
use dams::{
    crypto::{KeyId, OpaqueExportKey, StorageKey},
    dams_rpc::dams_rpc_client::DamsRpcClient,
    types::retrieve_storage_key::{client, server},
    user::UserId,
};
use tonic::transport::Channel;

mod generate;

#[allow(unused)]
const SECRET_LENGTH: u32 = 32;

impl DamsClient {
    /// Retrieve the [`Encrypted<StorageKey>`] that belongs to the user
    /// specified by `user_id`
    async fn retrieve_storage_key(
        &self,
        client: &mut DamsRpcClient<Channel>,
        export_key: OpaqueExportKey,
        user_id: &UserId,
    ) -> Result<StorageKey, DamsClientError> {
        // Create channel to send messages to server
        let mut channel = Self::create_channel(client, ClientAction::RetrieveStorageKey).await?;

        // Send UserId to server
        let request = client::Request {
            user_id: user_id.clone(),
        };
        channel.send(request).await?;

        // Get encrypted storage key from server
        let response: server::Response = channel.receive().await?;

        // Decrypt storage_key
        let storage_key = response
            .ciphertext
            .decrypt_storage_key(export_key, user_id)?;
        Ok(storage_key)
    }

    /// Generate and store an arbitrary secret at the key server
    pub async fn generate_and_store(
        &self,
        client: &mut DamsRpcClient<Channel>,
        user_id: &UserId,
        export_key: OpaqueExportKey,
    ) -> Result<KeyId, DamsClientError> {
        self.handle_generate(client, user_id, export_key).await
    }
}
