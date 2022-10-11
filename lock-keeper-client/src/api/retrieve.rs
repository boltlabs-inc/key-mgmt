use crate::{
    api::{LocalStorage, RetrieveResult},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::KeyId,
    infrastructure::channel::ClientChannel,
    types::operations::retrieve::{client, server, RetrieveContext},
};

impl LockKeeperClient {
    pub(crate) async fn handle_retrieve(
        &self,
        channel: &mut ClientChannel,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<RetrieveResult, LockKeeperClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key().await?;

        // TODO spec#39 look up key ID in local storage before making request to server

        // Send UserId to server
        let request = client::Request {
            user_id: self.user_id().clone(),
            key_id: key_id.clone(),
            context: context.clone(),
        };
        channel.send(request).await?;

        // Get StoredSecret from server
        let server_response: server::Response = channel.receive().await?;

        // Return appropriate value based on Context
        match context {
            RetrieveContext::Null => Ok(RetrieveResult::None),
            RetrieveContext::LocalOnly => {
                // Decrypt secret
                let secret = server_response
                    .stored_secret
                    .secret
                    .decrypt_secret(storage_key)?;
                let wrapped_secret = LocalStorage { secret };
                Ok(RetrieveResult::ArbitraryKey(wrapped_secret))
            }
        }
    }
}
