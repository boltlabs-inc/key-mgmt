use crate::{server::Context, DamsServerError};

use crate::error::LogExt;
use dams::{
    channel::ServerChannel,
    types::{
        retrieve::{client, server},
        Message, MessageStream,
    },
    ClientAction,
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
            retrieve(&mut channel, &context).await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn retrieve(channel: &mut ServerChannel, context: &Context) -> Result<(), DamsServerError> {
    // Receive UserId from client
    let request: client::Request = channel.receive().await?;

    // TODO #232: move this log so that we log the entire operation
    // Find secret based on key_id
    let stored_secret = context
        .db
        .get_user_secret(&request.user_id, &request.key_id)
        .await
        .log(
            &context.db,
            &request.user_id,
            Some(request.key_id),
            ClientAction::Retrieve,
        )
        .await?;

    // Serialize KeyId and send to client
    let reply = server::Response { stored_secret };
    channel.send(reply).await?;
    Ok(())
}
