use async_trait::async_trait;

use lock_keeper::{infrastructure::logging, types::audit_event::EventStatus};
use rand::rngs::StdRng;
use tracing::{error, info, instrument, Instrument};

use crate::{
    server::{database::DataStore, Context},
    LockKeeperServerError,
};

use super::channel::{Authenticated, Channel, Unauthenticated};

#[async_trait]
/// A type implementing [`Operation`] can process `tonic` requests using a
/// message-passing protocol facilitated by a [`Channel`].
pub(crate) trait Operation<AUTH: Send + 'static, DB: DataStore>:
    Sized + Send + 'static
{
    /// Core logic for a given operation.
    async fn operation(
        self,
        channel: &mut Channel<AUTH>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError>;
}

/// Takes a request from `tonic` and spawns a new thread to process that
/// request through the logic defined by the `Operation::operation` method.
/// Any errors returned by the operation are logged and an appropriate error
/// message is sent to the client.
#[instrument(skip_all, err(Debug), fields(metadata, request_id))]
pub(crate) async fn handle_authenticated_request<
    DB: DataStore,
    O: Operation<Authenticated<StdRng>, DB>,
>(
    operation: O,
    mut context: Context<DB>,
    mut channel: Channel<Authenticated<StdRng>>,
) -> Result<(), LockKeeperServerError> {
    logging::record_field("metadata", &channel.metadata());
    logging::record_field("request_id", &channel.metadata().request_id());
    info!("Handling new client request.");

    let _ = tokio::spawn(
        async move {
            audit_event(&mut channel, &context, EventStatus::Started).await;

            match operation.operation(&mut channel, &mut context).await {
                Ok(()) => {
                    info!("This operation completed successfully!");
                    audit_event(&mut channel, &context, EventStatus::Successful).await;
                }
                Err(e) => {
                    info!("This operation completed with an error!");
                    handle_error(&mut channel, e).await;
                    audit_event(&mut channel, &context, EventStatus::Failed).await;
                }
            }
            channel.closed().await;
        }
        .in_current_span(),
    );
    Ok(())
}

/// Takes a request from `tonic` and spawns a new thread to process that
/// request through the logic defined by the `Operation::operation` method.
/// Any errors returned by the operation are logged and an appropriate error
/// message is sent to the client.
#[instrument(skip_all, err(Debug), fields(metadata, request_id))]
pub(crate) async fn handle_unauthenticated_request<
    DB: DataStore,
    O: Operation<Unauthenticated, DB>,
>(
    operation: O,
    mut context: Context<DB>,
    mut channel: Channel<Unauthenticated>,
) -> Result<(), LockKeeperServerError> {
    logging::record_field("metadata", &channel.metadata());
    logging::record_field("request_id", &channel.metadata().request_id());
    info!("Handling new client request.");

    let _ = tokio::spawn(
        async move {
            match operation.operation(&mut channel, &mut context).await {
                Ok(()) => {
                    info!("This operation completed successfully!");
                }
                Err(e) => {
                    info!("This operation completed with an error!");
                    handle_error(&mut channel, e).await;
                }
            }
            channel.closed().await;
        }
        .in_current_span(),
    );
    Ok(())
}

#[instrument(skip(channel))]
async fn handle_error<AUTH>(channel: &mut Channel<AUTH>, e: LockKeeperServerError) {
    error!("{}", e);
    if let Err(e) = channel.send_error(e).await {
        error!("Problem while sending error over channel: {}", e);
    }
}

/// Log the given action as an audit event.
#[instrument(skip(channel, context))]
async fn audit_event<DB: DataStore>(
    channel: &mut Channel<Authenticated<StdRng>>,
    context: &Context<DB>,
    status: EventStatus,
) {
    let account_id = channel.account_id();
    let client_action = channel.metadata().action();
    let request_id = channel.metadata().request_id();

    let result = context
        .create_audit_event(account_id, request_id, client_action, status)
        .await;

    if let Err(e) = result {
        handle_error(channel, e).await;
    };
}
