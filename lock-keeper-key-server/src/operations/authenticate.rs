use crate::{
    error::LockKeeperServerError,
    server::{
        channel::{Channel, Unauthenticated},
        Context, Operation,
    },
};

use crate::server::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    infrastructure::logging,
    types::{
        audit_event::EventStatus,
        database::account::AccountId,
        operations::{
            authenticate::{client, server},
            ClientAction,
        },
    },
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};
use tracing::{debug, info, instrument};
use uuid::Uuid;

struct AuthenticateStartResult {
    login_start_result: ServerLoginStartResult<OpaqueCipherSuite>,
    account_id: AccountId,
    request_id: Uuid,
}

#[derive(Debug)]
pub struct Authenticate;

#[async_trait]
impl<DB: DataStore> Operation<Unauthenticated, DB> for Authenticate {
    /// Executes the sever-side opaque authentication protocol. This establishes
    /// a session key for client and server to use for secure communication.
    #[instrument(skip_all, err(Debug), fields(account_name))]
    async fn operation(
        self,
        channel: &mut Channel<Unauthenticated>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting authentication protocol.");

        let start_result = authenticate_start(channel, context).await?;

        // We do a bit of extra work here so that we can log audit events in case of
        // failure. This allows us to log failed login attempts.

        let account_id = start_result.account_id;
        let request_id = start_result.request_id;

        if let Err(e) = authenticate_finish(channel, context, start_result).await {
            context
                .create_audit_event(
                    account_id,
                    request_id,
                    ClientAction::Authenticate,
                    EventStatus::Failed,
                )
                .await?;
            return Err(e);
        }

        info!("Successfully completed authentication protocol.");
        Ok(())
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
#[instrument(skip_all, err(Debug), fields(account_id))]
async fn authenticate_start<DB: DataStore>(
    channel: &mut Channel<Unauthenticated>,
    context: &Context<DB>,
) -> Result<AuthenticateStartResult, LockKeeperServerError> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let account = context
        .db
        .find_account_by_name(&start_message.account_name)
        .await?
        .ok_or(LockKeeperServerError::InvalidAccount)?;

    logging::record_field("account_id", &account.account_id);
    debug!("Account found.");

    let account_id = account.id();
    let request_id = channel.metadata().request_id();

    // Manually log audit event for user whose account we found
    context
        .create_audit_event(
            account_id,
            request_id,
            ClientAction::Authenticate,
            EventStatus::Started,
        )
        .await?;

    let server_login_start_result = {
        let mut local_rng = context.rng.lock().await;

        ServerLogin::start(
            &mut *local_rng,
            &context.config.opaque_server_setup,
            Some(account.server_registration),
            start_message.credential_request,
            start_message.account_name.as_bytes(),
            ServerLoginStartParameters::default(),
        )?
    };

    let reply = server::AuthenticateStart {
        credential_response: server_login_start_result.message.clone(),
    };

    // Send response to client
    channel.send(reply).await?;

    Ok(AuthenticateStartResult {
        login_start_result: server_login_start_result,
        account_id,
        request_id,
    })
}

/// Second part of our sever-side authentication protocol. After this step, a
/// session key is established between server and client. This function returns
/// this key.
#[instrument(skip_all, err(Debug))]
async fn authenticate_finish<DB: DataStore>(
    channel: &mut Channel<Unauthenticated>,
    context: &mut Context<DB>,
    start_result: AuthenticateStartResult,
) -> Result<(), LockKeeperServerError> {
    // Receive finish message from client
    let finish_message: client::AuthenticateFinish = channel.receive().await?;

    let server_login_finish_result = start_result
        .login_start_result
        .state
        .finish(finish_message.credential_finalization)?;

    // Save session key into our cache.
    let session_cache = context.session_cache.lock().await;
    let session_key = server_login_finish_result.session_key.try_into()?;
    // Encrypt the session key and generate a new session ID.
    let encrypted_session_key = {
        let mut rng = context.rng.lock().await;
        context
            .config
            .remote_storage_key
            .encrypt_session_key(&mut *rng, session_key)?
    };

    let session_id = session_cache
        .create_session(start_result.account_id, encrypted_session_key)
        .await?;
    info!("Session key established and saved.");

    let reply = server::AuthenticateFinish { session_id };

    // Send response to client
    channel.send(reply).await?;

    // Manually log audit event for user who is now logged in
    context
        .create_audit_event(
            start_result.account_id,
            start_result.request_id,
            ClientAction::Authenticate,
            EventStatus::Successful,
        )
        .await?;

    Ok(())
}
