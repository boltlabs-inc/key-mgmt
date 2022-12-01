use async_trait::async_trait;
use lock_keeper::{
    constants::METADATA,
    infrastructure::channel::ServerChannel,
    types::{audit_event::EventStatus, operations::ResponseMetadata, Message, MessageStream},
};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

use crate::{database::DataStore, server::Context, LockKeeperServerError};

#[async_trait]
/// A type implementing [`Operation`] can process `tonic` requests using a
/// message-passing protocol facilitated by a [`ServerChannel`].
pub(crate) trait Operation<DB: DataStore>: Sized + Send + 'static {
    /// Core logic for a given operation.
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError>;

    /// Takes a request from `tonic` and spawns a new thread to process that
    /// request through the logic defined by the `Operation::operation` method.
    /// Any errors returned by the operation are logged and an appropriate error
    /// message is sent to the client.
    async fn handle_request(
        self,
        mut context: Context<DB>,
        request: Request<Streaming<Message>>,
    ) -> Result<Response<MessageStream>, Status> {
        let (mut channel, rx) = ServerChannel::create(request)?;

        {
            let mut session_key_cache = context.session_key_cache.lock().await;
            session_key_cache.check_key::<DB>(channel.metadata())?;
        }

        tracing::info!("Handling action: {:?}", channel.metadata().action());

        let _ = tokio::spawn(async move {
            audit_event(&mut channel, &context, EventStatus::Started).await;

            let result = self.operation(&mut channel, &mut context).await;
            if let Err(e) = result {
                handle_error(&mut channel, e).await;
                audit_event(&mut channel, &context, EventStatus::Failed).await;

                // Give the client a moment to receive the error before dropping the channel
                tokio::time::sleep(Duration::from_millis(10)).await;
            } else {
                audit_event(&mut channel, &context, EventStatus::Successful).await;
            }
        });

        let metadata = ResponseMetadata {
            request_id: Uuid::new_v4(),
        };

        let mut response = Response::new(ReceiverStream::new(rx));
        let _ = response
            .metadata_mut()
            .insert(METADATA, metadata.try_into()?);

        Ok(response)
    }
}

async fn handle_error(channel: &mut ServerChannel, e: LockKeeperServerError) {
    tracing::error!("{}", e);
    if let Err(e) = channel.send_error(e).await {
        tracing::error!("{}", e);
    }
}

async fn audit_event<DB: DataStore>(
    channel: &mut ServerChannel,
    context: &Context<DB>,
    status: EventStatus,
) {
    let account_name = channel.metadata().account_name();
    let action = channel.metadata().action();

    let audit_event = context
        .db
        .create_audit_event(account_name, &context.key_id, action, status)
        .await
        .map_err(|e| LockKeeperServerError::Database(Box::new(e)));
    if let Err(e) = audit_event {
        let _ = handle_error(channel, e);
    };
}
