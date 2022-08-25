use crate::{database::user as User, server::Context};

use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::{
        authenticate::{client, server},
        Message, MessageStream,
    },
};
use opaque_ke::{ServerLogin, ServerLoginStartParameters, ServerLoginStartResult};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct Authenticate;

impl Authenticate {
    pub async fn run(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, Status> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            let login_start_result = authenticate_start(&mut channel, &context).await?;
            authenticate_finish(&mut channel, login_start_result).await?;

            Ok::<(), Status>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Returns the server-side start message along with a login result that will be
/// used in the finish step.
async fn authenticate_start(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<ServerLoginStartResult<OpaqueCipherSuite>, Status> {
    // Receive start message from client
    let start_message: client::AuthenticateStart = channel.receive().await?;

    let server_setup = {
        let mut local_rng = context
            .rng
            .lock()
            .map_err(|_| Status::unavailable("Unable to access RNG"))?;
        create_or_retrieve_server_key_opaque(&mut local_rng, &context.service)
            .map_err(|_| Status::aborted("could not find/create server key"))?
    };

    // Check that user with corresponding UserId exists and get their
    // server_registration
    let server_registration = match User::find_user(&context.db, &start_message.user_id)
        .await
        .map_err(|_| Status::aborted("MongoDB error"))?
    {
        Some(user) => user.into_server_registration(),
        None => return Err(Status::aborted("UserId does not exist")),
    };

    let server_login_start_result = {
        let mut local_rng = context
            .rng
            .lock()
            .map_err(|_| Status::unavailable("Unable to access RNG"))?;

        match ServerLogin::start(
            &mut *local_rng,
            &server_setup,
            Some(server_registration),
            start_message.credential_request,
            start_message.user_id.as_bytes(),
            ServerLoginStartParameters::default(),
        ) {
            Ok(server_login_start_result) => server_login_start_result,
            Err(_) => return Err(Status::aborted("Server error")),
        }
    };

    let reply = server::AuthenticateStart {
        credential_response: server_login_start_result.message.clone(),
    };

    // Send response to client
    channel.send(reply).await?;

    Ok(server_login_start_result)
}

async fn authenticate_finish(
    channel: &mut ServerChannel,
    start_result: ServerLoginStartResult<OpaqueCipherSuite>,
) -> Result<(), Status> {
    // Receive finish message from client
    let finish_message: client::AuthenticateFinish = channel.receive().await?;

    match start_result
        .state
        .finish(finish_message.credential_finalization)
    {
        Ok(_) => {
            let reply = server::AuthenticateFinish { success: true };
            // Send response to client
            channel.send(reply).await?;
            Ok(())
        }
        Err(_) => Err(Status::unauthenticated("Could not authenticate")),
    }
}
