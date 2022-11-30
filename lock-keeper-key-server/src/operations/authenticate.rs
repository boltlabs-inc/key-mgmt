use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::OpaqueSessionKey,
    infrastructure::{channel::ServerChannel, logging},
    types::{
        database::user::UserId,
        operations::authenticate::{client, server},
    },
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};
use rand::{rngs::StdRng, CryptoRng, RngCore};
use tracing::{debug, info, instrument};

struct AuthenticateStartResult {
    login_start_result: ServerLoginStartResult<OpaqueCipherSuite>,
    user_id: UserId,
}

#[derive(Debug)]
pub struct Authenticate;

#[async_trait]
impl<DB: DataStore> Operation<DB> for Authenticate {
    /// Executes the sever-side opaque authentication protocol. This establishes
    /// a session key for client and server to use for secure communication.
    #[instrument(skip_all, err(Debug), fields(account_name))] // TODO: Record acccount name.
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting authentication protocol.");

        let result = authenticate_start(channel, context).await?;
        let session_key = authenticate_finish(channel, result.login_start_result).await?;

        // Save session key into our cache.
        let mut session_key_cache = context.session_key_cache.lock().await;
        session_key_cache.create_session(result.user_id.clone(), session_key.clone());
        info!("Session key established and saved.");

        channel.try_upgrade_to_authenticated(session_key)?;
        send_user_id(channel, result.user_id).await?;

        info!("Successfully completed authentication protocol.");
        Ok(())
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
#[instrument(skip_all, err(Debug), fields(user_id))]
async fn authenticate_start<DB: DataStore>(
    channel: &mut ServerChannel<StdRng>,
    context: &Context<DB>,
) -> Result<AuthenticateStartResult, LockKeeperServerError> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let (server_registration, user_id) = match context
        .db
        .find_user(&start_message.account_name)
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
async fn authenticate_finish<G: CryptoRng + RngCore>(
    channel: &mut ServerChannel<G>,
    start_result: ServerLoginStartResult<OpaqueCipherSuite>,
) -> Result<OpaqueSessionKey, LockKeeperServerError> {
    // Receive finish message from client
    let finish_message: client::AuthenticateFinish = channel.receive().await?;

    let server_login_finish_result = start_result
        .state
        .finish(finish_message.credential_finalization)?;
    let reply = server::AuthenticateFinish { success: true };

    // Send response to client
    channel.send(reply).await?;
    Ok(server_login_finish_result.session_key.try_into()?)
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
async fn send_user_id<G: CryptoRng + RngCore>(
    channel: &mut ServerChannel<G>,
    user_id: UserId,
) -> Result<(), LockKeeperServerError> {
    let reply = server::SendUserId { user_id };
    channel.send(reply).await?;
    Ok(())
}
