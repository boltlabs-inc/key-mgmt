use crate::{
    api::arbitrary_secrets::{Context, LocalStorage, RetrieveResult},
    DamsClient, DamsClientError,
};
use dams::{
    channel::ClientChannel,
    crypto::KeyId,
    types::retrieve::{client, server},
};

impl DamsClient {
    pub(crate) async fn handle_retrieve(
        &self,
        channel: &mut ClientChannel,
        key_id: &KeyId,
        context: Option<Context>,
    ) -> Result<RetrieveResult, DamsClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key().await?;

        // TODO spec#39 look up key ID in local storage before making request to server

        // Send UserId to server
        let request = client::Request {
            user_id: self.user_id().clone(),
            key_id: key_id.clone(),
        };
        channel.send(request).await?;

        // Get StoredSecret from server
        let server_response: server::Response = channel.receive().await?;

        // Decrypt secret
        let secret = server_response
            .stored_secret
            .secret
            .decrypt_secret(storage_key)?;

        // Return appropriate value based on Context
        match context {
            None => Ok(RetrieveResult::None),
            Some(Context::LocalOnly) => {
                let wrapped_secret = LocalStorage { secret };
                Ok(RetrieveResult::ArbitraryKey(wrapped_secret))
            }
            Some(Context::Export) => Ok(RetrieveResult::ExportedKey(secret.into())),
        }
    }
}
