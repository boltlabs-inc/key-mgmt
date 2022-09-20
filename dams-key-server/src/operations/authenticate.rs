use crate::{
    database::log::AuditLogExt,
    error::DamsServerError,
    server::{Context, Operation},
};

use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::authenticate::{client, server},
    user::{AccountName, UserId},
    ClientAction,
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};

struct AuthenticateStartResult {
    login_start_result: ServerLoginStartResult<OpaqueCipherSuite>,
    user_id: UserId,
    account_name: AccountName,
}

#[derive(Debug)]
pub struct Authenticate;

#[async_trait]
impl Operation for Authenticate {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        let AuthenticateStartResult {
            login_start_result,
            user_id,
            account_name,
        } = authenticate_start(channel, &context).await?;
        authenticate_finish(channel, login_start_result).await?;
        send_user_id(channel, user_id)
            .await
            .audit_log(&context.db, &account_name, None, ClientAction::Authenticate)
            .await?;

        Ok(())
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
async fn authenticate_start(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<AuthenticateStartResult, DamsServerError> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    let server_setup = {
        let mut local_rng = context.rng.lock().await;
        create_or_retrieve_server_key_opaque(&mut local_rng, &context.service)?
    };

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let (server_registration, user_id) =
        match context.db.find_user(&start_message.account_name).await? {
            Some(user) => user.into_parts(),
            None => return Err(DamsServerError::InvalidAccount),
        };

    let server_login_start_result = {
        let mut local_rng = context.rng.lock().await;

        ServerLogin::start(
            &mut *local_rng,
            &server_setup,
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
        account_name: start_message.account_name,
    })
}

async fn authenticate_finish(
    channel: &mut ServerChannel,
    start_result: ServerLoginStartResult<OpaqueCipherSuite>,
) -> Result<(), DamsServerError> {
    // Receive finish message from client
    let finish_message: client::AuthenticateFinish = channel.receive().await?;

    let _ = start_result
        .state
        .finish(finish_message.credential_finalization)?;
    let reply = server::AuthenticateFinish { success: true };

    // Send response to client
    channel.send(reply).await?;
    Ok(())
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
async fn send_user_id(channel: &mut ServerChannel, user_id: UserId) -> Result<(), DamsServerError> {
    let reply = server::SendUserId { user_id };
    channel.send(reply).await?;
    Ok(())
}
