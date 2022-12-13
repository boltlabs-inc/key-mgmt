use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::{
        database::user::UserId,
        operations::create_storage_key::{client, server},
    },
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
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting create storage key operation.");

        let user_id = send_user_id(channel, context).await?;
        store_storage_key(user_id, channel, context).await?;
        info!("Successfully finished set storage key protocol.");
        Ok(())
    }
}

/// Look up account and ensure the user doesn't already have a key stored.
/// 1) Get request from channel.
/// 2) Look up user in database.
/// 3) Ensure this user doesn't already have a storage key.
/// 4) Reply to client via channel.
#[instrument(skip_all, err(Debug))]
async fn send_user_id<DB: DataStore>(
    channel: &mut ServerChannel<Authenticated<StdRng>>,
    context: &Context<DB>,
) -> Result<UserId, LockKeeperServerError> {
    let request: client::RequestUserId = channel.receive().await?;
    info!(
        "Attempting to create storage key for {:?}",
        request.account_name
    );

    let user = context
        .db
        .find_user(&request.account_name)
        .await
        .map_err(LockKeeperServerError::database)?
        .ok_or(LockKeeperServerError::InvalidAccount)?;

    info!("User found: {:?}", user);

    if user.storage_key.is_some() {
        return Err(LockKeeperServerError::StorageKeyAlreadySet);
    }

    let reply = server::SendUserId {
        user_id: user.user_id.clone(),
    };

    channel.send(reply).await?;

    info!("Successfully completed create storage key protocol.");
    Ok(user.user_id)
}

#[instrument(skip_all, err(Debug), fields(user_id))]
async fn store_storage_key<DB: DataStore>(
    user_id: UserId,
    channel: &mut ServerChannel<Authenticated<StdRng>>,
    context: &Context<DB>,
) -> Result<(), LockKeeperServerError> {
    info!("Storing storage key.");
    let client_message: client::SendStorageKey = channel.receive().await?;

    if client_message.user_id != user_id {
        error!(
            "Newly received message contain a different user ID: ({:?})",
            client_message.user_id
        );
        return Err(LockKeeperServerError::InvalidAccount);
    }

    let store_key_result = context
        .db
        .set_storage_key(&user_id, client_message.storage_key)
        .await
        .map_err(|e| LockKeeperServerError::Database(Box::new(e)));

    // Delete user if we fail to set the storage key.
    if let Err(e) = store_key_result {
        error!("Failed to set storage key for user.");
        context
            .db
            .delete_user(&user_id)
            .await
            .map_err(LockKeeperServerError::database)?;
        info!("Deleted user due to failure to set storage key.");
        return Err(e);
    }

    let reply = server::CreateStorageKeyResult { success: true };
    channel.send(reply).await?;

    Ok(())
}
