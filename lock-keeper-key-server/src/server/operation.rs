use std::{thread, time::Duration};

use async_trait::async_trait;
use lock_keeper::{
    channel::ServerChannel,
    types::{Message, MessageStream},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::{server::Context, LockKeeperServerError};

#[async_trait]
/// A type implementing [`Operation`] can process `tonic` requests using a
/// message-passing protocol facilitated by a [`ServerChannel`].
pub(crate) trait Operation: Sized + Send + 'static {
    /// Core logic for a given operation.
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), LockKeeperServerError>;

    /// Takes a request from `tonic` and spawns a new thread to process that
    /// request through the logic defined by the `Operation::operation` method.
    /// Any errors returned by the operation are logged and an appropriate error
    /// message is sent to the client.
    async fn handle_request(
        self,
        context: Context,
        request: Request<Streaming<Message>>,
    ) -> Result<Response<MessageStream>, Status> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());
        let context = context;

        let _ = tokio::spawn(async move {
            let result = self.operation(&mut channel, context).await;
            if let Err(e) = result {
                tracing::error!("{}", e);
                if let Err(e) = channel.send_error(e).await {
                    tracing::error!("{}", e);
                }
                // Give the client a moment to receive the error before dropping the channel
                thread::sleep(Duration::from_millis(100));
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
