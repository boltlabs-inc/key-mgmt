use async_trait::async_trait;
use lock_keeper::{
    channel::ServerChannel,
    types::{Message, MessageStream},
    ClientAction,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    database::audit_event::AuditEventExt,
    server::{Context, OperationResult},
    LockKeeperServerError,
};

#[async_trait]
/// A type implementing [`Operation`] can process `tonic` requests using a
/// message-passing protocol facilitated by a [`ServerChannel`].
pub(crate) trait Operation: Sized + Send + 'static {
    /// Core logic for a given operation.
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &Context,
    ) -> Result<OperationResult, LockKeeperServerError>;

    /// Takes a request from `tonic` and spawns a new thread to process that
    /// request through the logic defined by the `Operation::operation` method.
    /// Any errors returned by the operation are logged and an appropriate error
    /// message is sent to the client.
    async fn handle_request(
        self,
        context: Context,
        request: Request<Streaming<Message>>,
        action: ClientAction,
    ) -> Result<Response<MessageStream>, Status> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());
        let context = context;

        let _ = tokio::spawn(async move {
            let _ = self
                .operation(&mut channel, &context)
                .await
                .log_audit_event(&mut channel, &context, action)
                .await;
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
