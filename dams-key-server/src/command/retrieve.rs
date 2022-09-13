use crate::{server::Context, DamsServerError};

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
    // Find secret based on key_id
    let stored_secret = context
        .db
        .get_user_secret(&request.user_id, request.key_id)
        .await?;
    // Serialize KeyId and send to client
    let reply = server::Response { stored_secret };
    channel.send(reply).await?;
    Ok(())
}
