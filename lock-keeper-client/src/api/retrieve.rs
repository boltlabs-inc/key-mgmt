use crate::{
    api::LocalStorage,
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::{Encrypted, KeyId, Secret, SigningKeyPair},
    types::{
        database::secrets::secret_types,
        operations::retrieve_secret::{client, server, RetrieveContext},
    },
};
use rand::rngs::StdRng;
use uuid::Uuid;

impl LockKeeperClient {
    /// Handles the retrieval of arbitrary secrets
    /// ([`lock_keeper::crypto::Secret`]) only.
    pub(crate) async fn handle_retrieve_secret(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_id: &KeyId,
        context: RetrieveContext,
        request_id: Uuid,
    ) -> Result<Option<LocalStorage<Secret>>, LockKeeperClientError> {
        // Retrieve the storage key
        let storage_key = self.retrieve_storage_key(request_id).await?;

        // TODO spec#39 look up key ID in local storage before making request to server

        // Send UserId to server
        let request = client::Request {
            key_id: key_id.clone(),
            context: context.clone(),
            secret_type: Some(secret_types::ARBITRARY_SECRET.to_string()),
        };
        channel.send(request).await?;

        // Get StoredSecret from server
        let server_response: server::Response = channel.receive().await?;
        let secret: Encrypted<Secret> = server_response.secret.try_into()?;

        // Return appropriate value based on Context
        let result = match context {
            RetrieveContext::Null => None,
            RetrieveContext::LocalOnly => {
                // Decrypt secret
                let secret = secret.decrypt_secret(storage_key)?;
                let wrapped_secret = LocalStorage { material: secret };
                Some(wrapped_secret)
            }
        };

        Ok(result)
    }

    /// Handles the retrieval of signing keys
    /// ([`lock_keeper::crypto::SigningKeyPair`]) only.
    pub(crate) async fn handle_retrieve_signing_key(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_id: &KeyId,
        context: RetrieveContext,
    ) -> Result<Option<LocalStorage<SigningKeyPair>>, LockKeeperClientError> {
        // TODO spec#39 look up key ID in local storage before making request to server
        let request = client::Request {
            key_id: key_id.clone(),
            context: context.clone(),
            secret_type: Some(secret_types::REMOTE_SIGNING_KEY.to_string()),
        };
        channel.send(request).await?;

        // Get StoredSigningKeyPair type back from server
        let server_response: server::Response = channel.receive().await?;
        let key_pair: SigningKeyPair = server_response.secret.try_into()?;

        // Return appropriate value based on Context
        let result = match context {
            RetrieveContext::Null => None,
            RetrieveContext::LocalOnly => {
                let wrapped_signing_key = LocalStorage { material: key_pair };
                Some(wrapped_signing_key)
            }
        };

        Ok(result)
    }
}
