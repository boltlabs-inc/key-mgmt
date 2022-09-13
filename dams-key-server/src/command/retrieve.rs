use crate::{database::user as User, server::Context, DamsServerError};

use dams::{
    channel::ServerChannel,
    types::{
        retrieve::{client, server},
        Message, MessageStream,
    },
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

#[derive(Debug)]
pub struct Retrieve;

impl Retrieve {
    pub async fn run<'a>(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, DamsServerError> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            // Generate step: receive UserId and reply with new KeyId
            retrieve(&mut channel, &context).await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn retrieve(channel: &mut ServerChannel, context: &Context) -> Result<(), DamsServerError> {
    // Receive UserId from client
    let request: client::Request = channel.receive().await?;
    // Find user by ID
    let user = User::find_user_by_id(&context.db, &request.user_id)
        .await?
        .ok_or(DamsServerError::AccountDoesNotExist)?;

    // Find secret based on key_id
    let stored_secret = user
        .secrets
        .into_iter()
        .find(|x| x.key_id == request.key_id)
        .ok_or(DamsServerError::KeyNotFound)?;

    // Serialize KeyId and send to client
    let reply = server::Response { stored_secret };
    channel.send(reply).await?;
    Ok(())
}
