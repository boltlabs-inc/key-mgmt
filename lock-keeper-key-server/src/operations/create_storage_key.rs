use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::{
        database::user::UserId,
        operations::create_storage_key::{client, server},
    },
};
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct CreateStorageKey;

#[async_trait]
impl<DB: DataStore> Operation<DB> for CreateStorageKey {
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        let user_id = send_user_id(channel, context).await?;
        store_storage_key(user_id, channel, context).await?;
        Ok(())
    }
}

async fn send_user_id<DB: DataStore>(
    channel: &mut ServerChannel<StdRng>,
    context: &Context<DB>,
) -> Result<UserId, LockKeeperServerError> {
    let request: client::RequestUserId = channel.receive().await?;
    let user = context
        .db
        .find_user(&request.account_name)
        .await
        .map_err(LockKeeperServerError::database)?;

    if let Some(user) = user {
        if user.storage_key.is_some() {
            return Err(LockKeeperServerError::StorageKeyAlreadySet);
        }

        let reply = server::SendUserId {
            user_id: user.user_id.clone(),
        };

        channel.send(reply).await?;

        Ok(user.user_id)
    } else {
        Err(LockKeeperServerError::InvalidAccount)
    }
}

async fn store_storage_key<DB: DataStore>(
    user_id: UserId,
    channel: &mut ServerChannel<StdRng>,
    context: &Context<DB>,
) -> Result<(), LockKeeperServerError> {
    let client_message: client::SendStorageKey = channel.receive().await?;

    if client_message.user_id != user_id {
        return Err(LockKeeperServerError::InvalidAccount);
    }

    if let Err(error) = context
        .db
        .set_storage_key(&user_id, client_message.storage_key)
        .await
        .map_err(|e| LockKeeperServerError::Database(Box::new(e)))
    {
        context
            .db
            .delete_user(&user_id)
            .await
            .map_err(LockKeeperServerError::database)?;
        return Err(error);
    }

    let reply = server::CreateStorageKeyResult { success: true };
    channel.send(reply).await?;

    Ok(())
}
