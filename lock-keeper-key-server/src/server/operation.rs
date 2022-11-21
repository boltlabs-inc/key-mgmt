use async_trait::async_trait;
use lock_keeper::{
    constants::METADATA,
    infrastructure::channel::ServerChannel,
    types::{
        audit_event::EventStatus,
        database::user::UserId,
        operations::{ClientAction, ResponseMetadata},
        Message, MessageStream,
    },
};

use lock_keeper::crypto::OpaqueSessionKey;
use std::{ops::DerefMut, time::Duration};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, Instrument};
use uuid::Uuid;

use crate::{
    database::DataStore,
    server::{session_key_cache::SessionKeyCache, Context},
    LockKeeperServerError,
};

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
        info!("Handling new client request.");
        let (mut channel, rx) = ServerChannel::create(request, None)?;

        let _ = tokio::spawn(async move {
            audit_event(&mut channel, &context, EventStatus::Started).await;

            let result = self.operation(&mut channel, &mut context).await;
            if let Err(e) = result {
                handle_error(&mut channel, e).await;
                audit_event(&mut channel, &context, EventStatus::Failed).await;

                // Give the client a moment to receive the error before dropping the channel
                thread::sleep(Duration::from_millis(100));
            } else {
                audit_event(&mut channel, &context, EventStatus::Successful).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn handle_authenticated_request(
        self,
        mut context: Context<DB>,
        request: Request<Streaming<Message>>,
    ) -> Result<Response<MessageStream>, Status> {
        info!("Handling new client request.");
        let (mut channel, rx) = ServerChannel::create(request, None)?;
        let session_key = {
            let session_cache = context.session_key_cache.lock().await;
            check_authentication(
                &channel.metadata().action(),
                channel.metadata().user_id().as_ref(),
                session_cache,
            )?
        };
        //TODO: upgrade channel
        tracing::info!("Handling action: {:?}", context.metadata.action());

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

/// Most operations require an authenticated session. Check if there is a valid
/// session.
fn check_authentication(
    action: &ClientAction,
    user_id: Option<&UserId>,
    mut session_cache: impl DerefMut<Target = SessionKeyCache>,
) -> Result<OpaqueSessionKey, LockKeeperServerError> {
    info!("Checking client's authentication...");
    match action {
        // These actions are unauthenticated.
        ClientAction::Authenticate | ClientAction::Register => {
            error!("Protocol does not require client to be authenticated.");
            Err(LockKeeperServerError::UnauthenticatedChannelNeeded)
        }
        // The rest of the actions must be authenticated
        _ => {
            let user_id = user_id.ok_or(LockKeeperServerError::InvalidAccount)?;
            let session_key = session_cache
                .get_key(user_id.clone())
                .map_err(LockKeeperServerError::SessionKeyCache)?;

            info!("User is already authenticated.");
            Ok(session_key)
        }
    }
}

async fn handle_error(channel: &mut ServerChannel, e: LockKeeperServerError) {
    error!("{}", e);
    if let Err(e) = channel.send_error(e).await {
        error!("Problem while sending error over channel: {}", e);
    }
}

/// Log the given action as an audit event.
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
