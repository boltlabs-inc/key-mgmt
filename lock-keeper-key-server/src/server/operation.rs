use async_trait::async_trait;
use lock_keeper::{
    audit_event::EventStatus,
    channel::ServerChannel,
    types::{Message, MessageStream},
};
use std::{thread, time::Duration};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::{
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
        context: &mut Context,
    ) -> Result<OperationResult, LockKeeperServerError>;

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
        let mut context = context;

        let _ = tokio::spawn(async move {
            Self::audit_event(&mut channel, &context, EventStatus::Started).await;
            let result = self.operation(&mut channel, &mut context).await;
            if let Err(e) = result {
                Self::handle_error(&mut channel, e).await;
                Self::audit_event(&mut channel, &context, EventStatus::Failed).await;

                // Give the client a moment to receive the error before dropping the channel
                thread::sleep(Duration::from_millis(100));
            } else {
                Self::audit_event(&mut channel, &context, EventStatus::Successful).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn handle_error(channel: &mut ServerChannel, e: LockKeeperServerError) {
        tracing::error!("{}", e);
        if let Err(e) = channel.send_error(e).await {
            tracing::error!("{}", e);
        }
    }

    async fn audit_event(channel: &mut ServerChannel, context: &Context, status: EventStatus) {
        let audit_event = context
            .db
            .create_audit_event(
                &context.account_name,
                &context.key_id,
                &context.action,
                status,
            )
            .await;
        if let Err(e) = audit_event {
            let _ = Self::handle_error(channel, e);
        };
    }
}
