use crate::{
    server::{
        channel::{Authenticated, Channel},
        database::{DataStore, SecretFilter},
        Context, Operation,
    },
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    crypto::{DataBlob, Encrypted},
    types::{
        database::secrets::secret_types::SERVER_ENCRYPTED_BLOB,
        operations::retrieve_server_encrypted_blob::{client, server},
    },
    LockKeeperError,
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveServerEncryptedBlob;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RetrieveServerEncryptedBlob {
    #[instrument(skip_all, err(Debug))]
    /// 1) Accept a key ID from client which references a stored [DataBlob].
    /// 2) Retrieve the encrypted data blob from database.
    /// 3) Decrypt data blob using server's (remote) storage key.
    /// 4) Return decrypted storage key to client.
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve server-encrypted blob protocol.");
        let request: client::Request = channel.receive().await?;
        // We cannot inline this expression, or Rust will complain about holding
        // references across `await` in a future.
        let account_id = channel.account_id();
        context.key_id = Some(request.key_id.clone());

        let stored_secret = context
            .db
            .get_secret(
                account_id,
                &request.key_id,
                SecretFilter::secret_type(SERVER_ENCRYPTED_BLOB),
            )
            .await?;

        let blob: Encrypted<DataBlob> =
            serde_json::from_slice(&stored_secret.bytes).map_err(LockKeeperError::SerdeJson)?;
        let blob = blob.decrypt_data_blob(&context.config.remote_storage_key)?;

        channel
            .send(server::Response {
                data_blob: blob.blob_data(),
            })
            .await?;

        info!("Successfully completed retrieve server-encrypted blob protocol.");
        Ok(())
    }
}
