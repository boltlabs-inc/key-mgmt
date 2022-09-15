use crate::{
    server::{Context, Operation},
    DamsServerError,
};
use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    types::retrieve_storage_key::{client, server},
};

#[derive(Debug)]
pub struct RetrieveStorageKey;

#[async_trait]
impl Operation for RetrieveStorageKey {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        // Receive user ID and retrieve encrypted storage key for that user
        let request: client::Request = channel.receive().await?;

        // Find user by ID
        let user = context
            .db
            .find_user_by_id(&request.user_id)
            .await?
            .ok_or(DamsServerError::InvalidAccount)?;

        // Send storage key if set
        let storage_key = user.storage_key.ok_or(DamsServerError::StorageKeyNotSet)?;
        let reply = server::Response {
            ciphertext: storage_key,
        };
        channel.send(reply).await?;

        Ok(())
    }
}
