use async_trait::async_trait;
use lock_keeper::{
    infrastructure::{channel::ServerChannel, logging},
    types::audit_event::EventStatus,
};
use std::time::Duration;
use tracing::{error, info, instrument, Instrument};

use crate::{database::DataStore, server::Context, LockKeeperServerError};

#[async_trait]
/// A type implementing [`Operation`] can process `tonic` requests using a
/// message-passing protocol facilitated by a [`ServerChannel`].
pub(crate) trait Operation<AUTH: Send + 'static, DB: DataStore>:
    Sized + Send + 'static
{
    /// Core logic for a given operation.
    async fn operation(
        self,
        channel: &mut ServerChannel<AUTH>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError>;

    /// Takes a request from `tonic` and spawns a new thread to process that
    /// request through the logic defined by the `Operation::operation` method.
    /// Any errors returned by the operation are logged and an appropriate error
    /// message is sent to the client.
    #[instrument(skip_all, err(Debug), fields(metadata, request_id))]
    async fn handle_request(
        self,
        mut context: Context<DB>,
        mut channel: ServerChannel<AUTH>,
    ) -> Result<(), LockKeeperServerError> {
        logging::record_field("metadata", &channel.metadata());
        logging::record_field("request_id", &channel.metadata().request_id());
        info!("Handling new client request.");

        let _ = tokio::spawn(
            async move {
                audit_event(&mut channel, &context, EventStatus::Started).await;

                match self.operation(&mut channel, &mut context).await {
                    Ok(()) => {
                        info!("This operation completed successfully!");
                        audit_event(&mut channel, &context, EventStatus::Successful).await;
                    }
                    Err(e) => {
                        info!("This operation completed with an error!");
                        handle_error(&mut channel, e).await;
                        audit_event(&mut channel, &context, EventStatus::Failed).await;

                        // Give the client a moment to receive the error before dropping the channel
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
            .in_current_span(),
        );
        Ok(())
    }
}

#[instrument(skip_all, fields(e))]
async fn handle_error<AUTH>(channel: &mut ServerChannel<AUTH>, e: LockKeeperServerError) {
    error!("{}", e);
    if let Err(e) = channel.send_error(e).await {
        error!("Problem while sending error over channel: {}", e);
    }
}

/// Log the given action as an audit event.
#[instrument(skip_all, fields(status))]
async fn audit_event<AUTH, DB: DataStore>(
    channel: &mut ServerChannel<AUTH>,
    context: &Context<DB>,
    status: EventStatus,
) {
    let account_name = channel.metadata().account_name();
    let action = channel.metadata().action();
    let request_id = channel.metadata().request_id();

    let audit_event = context
        .db
        .create_audit_event(request_id, account_name, &context.key_id, action, status)
        .await
        .map_err(|e| LockKeeperServerError::Database(Box::new(e)));
    if let Err(e) = audit_event {
        let _ = handle_error(channel, e);
    };
}
