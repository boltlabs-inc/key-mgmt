use crate::{
    error::DamsServerError,
    server::{Context, Operation},
};

use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    types::create_storage_key::{client, server},
    user::UserId,
};

#[derive(Debug)]
pub struct CreateStorageKey;

#[async_trait]
impl Operation for CreateStorageKey {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        let user_id = send_user_id(channel, &context).await?;
        store_storage_key(user_id, channel, &context).await?;
        Ok(())
    }
}

async fn send_user_id(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<UserId, DamsServerError> {
    let request: client::RequestUserId = channel.receive().await?;
    let user = context.db.find_user(&request.account_name).await?;

    if let Some(user) = user {
        if user.storage_key.is_some() {
            return Err(DamsServerError::StorageKeyAlreadySet);
        }

        let reply = server::SendUserId {
            user_id: user.user_id.clone(),
        };

        channel.send(reply).await?;

        Ok(user.user_id)
    } else {
        Err(DamsServerError::InvalidAccount)
    }
}

async fn store_storage_key(
    user_id: UserId,
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    let client_message: client::SendStorageKey = channel.receive().await?;

    if client_message.user_id != user_id {
        return Err(DamsServerError::InvalidAccount);
    }

    if let Err(error) = context
        .db
        .set_storage_key(&user_id, client_message.storage_key)
        .await
    {
        context.db.delete_user(&user_id).await?;
        return Err(error);
    }

    let reply = server::CreateStorageKeyResult { success: true };
    channel.send(reply).await?;

    Ok(())
}
