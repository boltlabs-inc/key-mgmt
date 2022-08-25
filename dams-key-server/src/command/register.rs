use crate::{database::user as User, server::Context};

use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::{
        register::{client, server},
        Message, MessageStream,
    },
};
use opaque_ke::ServerRegistration;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

#[derive(Debug)]
pub struct Register;

impl Register {
    pub async fn run<'a>(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, Status> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            register_start(&mut channel, &context).await?;
            register_finish(&mut channel, &context).await?;

            Ok::<(), Status>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn register_start(channel: &mut ServerChannel, context: &Context) -> Result<(), Status> {
    // Receive start message from client
    let start_message: client::RegisterStart = channel.receive().await?;

    // Get server key for OPAQUE
    let server_setup = {
        let mut rng = context
            .rng
            .lock()
            .map_err(|_| Status::unavailable("Unable to access RNG"))?;

        create_or_retrieve_server_key_opaque(&mut rng, &context.service)
            .map_err(|_| Status::aborted("could not find/create server key"))?
    };

    // Abort registration if UserId already exists
    if User::find_user(&context.db, &start_message.user_id)
        .await
        .map_err(|_| Status::aborted("MongoDB error"))?
        .is_some()
    {
        Err(Status::already_exists("UserID already exists"))
    } else {
        // Registration can continue if user ID doesn't exist yet
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            start_message.registration_request,
            start_message.user_id.as_bytes(),
        )
        .map_err(|_| Status::aborted("Could not start server registration"))?;

        let reply = server::RegisterStart {
            registration_response: server_registration_start_result.message,
        };

        // Send response to client
        channel.send(reply).await?;

        Ok(())
    }
}

async fn register_finish(channel: &mut ServerChannel, context: &Context) -> Result<(), Status> {
    // Receive finish message from client
    let finish_message: client::RegisterFinish = channel.receive().await?;

    // run the finish step for OPAQUE
    let server_registration =
        ServerRegistration::<OpaqueCipherSuite>::finish(finish_message.registration_upload);

    // add the new user to the DB
    let _object_id = User::create_user(&context.db, &finish_message.user_id, server_registration)
        .await
        .map_err(|_| Status::aborted("Unable to create user"))?
        .ok_or_else(|| Status::aborted("Invalid ObjectId for new user"))?;

    // reply with the success:true if successful
    let reply = server::RegisterFinish { success: true };

    // Send response to client
    channel.send(reply).await?;

    Ok(())
}
