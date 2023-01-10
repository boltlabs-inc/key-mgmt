use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    infrastructure::{
        channel::{ServerChannel, Unauthenticated},
        logging,
    },
    types::{
        database::user::UserId,
        operations::authenticate::{client, server},
    },
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};
use tracing::{debug, info, instrument};

struct AuthenticateStartResult {
    login_start_result: ServerLoginStartResult<OpaqueCipherSuite>,
    user_id: UserId,
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
        channel: &mut ServerChannel<Unauthenticated>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting authentication protocol.");

        let start_result = authenticate_start(channel, context).await?;
        authenticate_finish(channel, start_result, context).await?;

        info!("Successfully completed authentication protocol.");
        Ok(())
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
#[instrument(skip_all, err(Debug), fields(user_id))]
async fn authenticate_start<DB: DataStore>(
    channel: &mut ServerChannel<Unauthenticated>,
    context: &Context<DB>,
) -> Result<AuthenticateStartResult, LockKeeperServerError> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let (server_registration, user_id) = match context
        .db
        .find_account(&start_message.account_name)
        .await
        .map_err(LockKeeperServerError::database)?
    {
        Some(user) => user.into_parts(),
        None => return Err(LockKeeperServerError::InvalidAccount),
    };

    logging::record_field("user_id", &user_id);
    debug!("User ID found.");

    let server_login_start_result = {
        let mut local_rng = context.rng.lock().await;

        ServerLogin::start(
            &mut *local_rng,
            &context.config.opaque_server_setup,
            Some(server_registration),
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
        user_id,
    })
}

/// Second part of our sever-side authentication protocol. After this step, a
/// session key is established between server and client. This function returns
/// this key.
#[instrument(skip_all, err(Debug))]
async fn authenticate_finish<DB: DataStore>(
    channel: &mut ServerChannel<Unauthenticated>,
    start_result: AuthenticateStartResult,
    context: &mut Context<DB>,
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
        .create_session(start_result.user_id.clone(), encrypted_session_key)
        .await?;
    info!("Session key established and saved.");

    let reply = server::AuthenticateFinish { session_id };

    // Send response to client
    channel.send(reply).await?;
    Ok(())
}
