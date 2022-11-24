use crate::{api::LocalStorage, LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use lock_keeper::{
    crypto::{KeyId, Secret, SigningKeyPair},
    infrastructure::channel::ClientChannel,
    types::operations::retrieve::{client, server, RetrieveContext},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    /// Handles the retrieval of arbitrary secrets
    /// ([`lock_keeper::crypto::Secret`]) only.
    pub(crate) async fn handle_retrieve(
        &self,
        mut channel: ClientChannel<StdRng>,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<LockKeeperResponse<Option<LocalStorage<Secret>>>, LockKeeperClientError> {
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
        let result = match context {
            RetrieveContext::Null => None,
            RetrieveContext::LocalOnly => {
                // Decrypt secret
                let secret = server_response
                    .stored_secret
                    .secret
                    .decrypt_secret(storage_key)?;
                let wrapped_secret = LocalStorage { material: secret };
                Some(wrapped_secret)
            }
        };

        Ok(LockKeeperResponse::from_channel(channel, result))
    }

    /// Handles the retrieval of signing keys
    /// ([`lock_keeper::crypto::SigningKeyPair`]) only.
    pub(crate) async fn handle_retrieve_signing_key(
        &self,
        mut channel: ClientChannel<StdRng>,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<LockKeeperResponse<Option<LocalStorage<SigningKeyPair>>>, LockKeeperClientError>
    {
        // TODO spec#39 look up key ID in local storage before making request to server

        // Send UserId to server
        let request = client::RequestSigningKey {
            user_id: self.user_id().clone(),
            key_id: key_id.clone(),
            context: context.clone(),
        };
        channel.send(request).await?;

        // Get StoredSigningKeyPair type back from server
        let server_response: server::ResponseSigningKey = channel.receive().await?;

        // Return appropriate value based on Context
        let result = match context {
            RetrieveContext::Null => None,
            RetrieveContext::LocalOnly => {
                let signing_key_pair: SigningKeyPair = server_response
                    .stored_signing_key
                    .signing_key
                    .to_owned()
                    .try_into()?;
                let wrapped_signing_key = LocalStorage {
                    material: signing_key_pair,
                };
                Some(wrapped_signing_key)
            }
        };

        Ok(LockKeeperResponse::from_channel(channel, result))
    }
}
