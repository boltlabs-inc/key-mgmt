use crate::{
    error::LockKeeperServerError,
    server::{
        channel::{Authenticated, Channel},
        Context, Operation,
    },
};

use crate::server::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::logging,
    types::operations::create_storage_key::{client, server},
};
use rand::rngs::StdRng;
use tracing::{error, info, instrument};

#[derive(Debug)]
pub struct CreateStorageKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for CreateStorageKey {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting create storage key operation.");

        store_storage_key(channel, context).await?;
        info!("Successfully finished set storage key protocol.");

        Ok(())
    }
}

/// Look up account and ensure the user doesn't already have a key stored.
/// 1) Get request from channel.
/// 2) Look up user in database.
/// 3) Ensure this user doesn't already have a storage key.
/// 4) Reply to client via channel.
#[instrument(skip_all, err(Debug), fields(account_id))]
async fn store_storage_key<DB: DataStore>(
    channel: &mut Channel<Authenticated<StdRng>>,
    context: &Context<DB>,
) -> Result<(), LockKeeperServerError> {
    info!("Storing storage key.");
    let client_message: client::SendStorageKey = channel.receive().await?;

    let account_id = channel.account_id();
    logging::record_field("account_id", &account_id);

    if channel.account().storage_key.is_some() {
        return Err(LockKeeperServerError::StorageKeyAlreadySet);
    }

    let store_key_result = context
        .db
        .set_storage_key(account_id, client_message.storage_key.clone())
        .await;

    // Delete user if we fail to set the storage key.
    if let Err(e) = store_key_result {
        error!("Failed to set storage key for user.");
        context.db.delete_account(account_id).await?;
        info!("Deleted user due to failure to set storage key.");
        return Err(e.into());
    }

    let reply = server::CreateStorageKeyResult { success: true };
    channel.send(reply).await?;

    // Set the storage key in the cached account data stored in the channel.
    channel.set_storage_key(client_message.storage_key);

    Ok(())
}
