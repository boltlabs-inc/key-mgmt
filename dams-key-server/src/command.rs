pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod register;
pub mod retrieve;

use crate::{server::Context, DamsServerError};
use dams::{
    channel::ServerChannel,
    types::{
        retrieve_storage_key::{client, server},
        Message, MessageStream,
    },
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

pub async fn retrieve_storage_key(
    request: Request<tonic::Streaming<Message>>,
    context: Context,
) -> Result<Response<MessageStream>, DamsServerError> {
    let (mut channel, rx) = ServerChannel::create(request.into_inner());

    let _ = tokio::spawn(async move {
        // Receive user ID and retrieve encrypted storage key for that user
        handle_retrieve_storage_key(&mut channel, &context).await?;
        Ok::<(), DamsServerError>(())
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}

async fn handle_retrieve_storage_key(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    let request: client::Request = channel.receive().await?;
    // Find user by ID
    let user = context
        .db
        .find_user_by_id(&request.user_id)
        .await?
        .ok_or(DamsServerError::AccountDoesNotExist)?;
    // Send storage key if set
    let storage_key = user.storage_key.ok_or(DamsServerError::StorageKeyNotSet)?;
    let reply = server::Response {
        ciphertext: storage_key,
    };
    channel.send(reply).await?;

    Ok(())
}
