use crate::{
    server::{
        channel::{Authenticated, Channel},
        database::DataStore,
        Context, Operation,
    },
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    crypto::{DataBlob, KeyId},
    types::{
        database::secrets::StoredSecret,
        operations::store_server_encrypted_blob::{client, server},
    },
};
use metered::measure;
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct StoreServerEncryptedBlob;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for StoreServerEncryptedBlob {
    #[instrument(skip_all, err(Debug))]
    /// 1) Accept data blob from client.
    /// 2) Ensure data blob is below maximum allowed size.
    /// 3) Generate a new key ID for data blob.
    /// 4) Encrypt blob using server's (remote) storage key.
    /// 5) Store blob in our database as a StoredSecret.
    /// 6) Respond to client with key ID.
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting store server-encrypted blob protocol.");

        measure!(&context.operation_metrics.store_blob_total, {
            let request: client::Request = channel.receive().await?;
            let user_id = channel.user_id();

            // Check size of blob.
            if request.data_blob.len() > context.config.max_blob_size as usize {
                return Err(LockKeeperServerError::BlobSizeTooLarge);
            }

            // Generate new KeyId
            let key_id = {
                let mut rng = context.rng.lock().await;
                KeyId::generate(&mut *rng, user_id)?
            };
            context.key_id = Some(key_id.clone());

            // Create a new data blob from client's data.
            let blob = DataBlob::create(request.data_blob, user_id, &key_id)?;

            let encrypted_blob = {
                let mut rng = context.rng.lock().await;
                context
                    .config
                    .remote_storage_key
                    .encrypt_data_blob(&mut *rng, blob)?
            };

            let secret =
                StoredSecret::from_data_blob(key_id.clone(), channel.account_id(), encrypted_blob)?;

            measure!(&context.operation_metrics.store_blob_database, {
                context.db.add_secret(secret).await?;
            });

            channel.send(server::Response { key_id }).await?;
        });

        info!("Successfully completed store server-encrypted blob protocol.");
        Ok(())
    }
}
