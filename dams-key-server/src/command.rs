pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod register;

use crate::{server::Context, DamsServerError};
use dams::{
    channel::ServerChannel,
    types::{retrieve_storage_key::client, Message, MessageStream},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

pub async fn retrieve_storage_key(
    request: Request<tonic::Streaming<Message>>,
    _context: Context,
) -> Result<Response<MessageStream>, DamsServerError> {
    let (mut channel, rx) = ServerChannel::create(request.into_inner());

    let _ = tokio::spawn(async move {
        // Receive user ID and retrieve encrypted storage key for that user
        let _request: client::Request = channel.receive().await?;
        // TODO #133 (implementation): get and return storage key from DB once flow has
        // been decided
        Ok::<(), DamsServerError>(())
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}
