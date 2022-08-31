use crate::{database::user as User, error::DamsServerError, server::Context};

use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::{
        authenticate::{client, server},
        Message, MessageStream,
    },
    user::UserId,
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response};

#[derive(Debug)]
pub struct Authenticate;

impl Authenticate {
    pub async fn run(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, DamsServerError> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            let (login_start_result, user_id) = authenticate_start(&mut channel, &context).await?;
            authenticate_finish(&mut channel, login_start_result).await?;
            send_user_id(&mut channel, user_id).await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
async fn authenticate_start(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(ServerLoginStartResult<OpaqueCipherSuite>, UserId), DamsServerError> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    let server_setup = {
        let mut local_rng = context.rng.lock().await;
        create_or_retrieve_server_key_opaque(&mut local_rng, &context.service)?
    };

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let (server_registration, user_id) =
        match User::find_user(&context.db, &start_message.account_name).await? {
            Some(user) => user.into_parts(),
            None => return Err(DamsServerError::AccountDoesNotExist),
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

    Ok((server_login_start_result, user_id))
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
