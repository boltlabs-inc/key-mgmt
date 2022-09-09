use crate::{
    database::user::{delete_user, find_user, set_storage_key},
    error::DamsServerError,
    server::Context,
};

use dams::{
    channel::ServerChannel,
    types::{
        create_storage_key::{client, server},
        Message, MessageStream,
    },
    user::UserId,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

#[derive(Debug)]
pub struct CreateStorageKey;

impl CreateStorageKey {
    pub async fn run<'a>(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, DamsServerError> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            let user_id = send_user_id(&mut channel, &context).await?;
            store_storage_key(user_id, &mut channel, &context).await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn send_user_id(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<UserId, DamsServerError> {
    let request: client::RequestUserId = channel.receive().await?;
    let user = find_user(&context.db, &request.account_name).await?;

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
        Err(DamsServerError::AccountDoesNotExist)
    }
}

async fn store_storage_key(
    user_id: UserId,
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    let client_message: client::SendStorageKey = channel.receive().await?;

    if client_message.user_id != user_id {
        return Err(DamsServerError::InvalidUserId);
    }

    if let Err(error) = set_storage_key(&context.db, &user_id, client_message.storage_key).await {
        delete_user(&context.db, &user_id).await?;
        return Err(error);
    }

    let reply = server::CreateStorageKeyResult { success: true };
    channel.send(reply).await?;

    Ok(())
}
