use crate::{database::user as User, error::DamsServerError, server::Context};

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
use tonic::{Request, Response};

#[derive(Debug)]
pub struct Register;

impl Register {
    pub async fn run<'a>(
        &self,
        request: Request<tonic::Streaming<Message>>,
        context: Context,
    ) -> Result<Response<MessageStream>, DamsServerError> {
        let (mut channel, rx) = ServerChannel::create(request.into_inner());

        let _ = tokio::spawn(async move {
            register_start(&mut channel, &context).await?;
            register_finish(&mut channel, &context).await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn register_start(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    // Receive start message from client
    let start_message: client::RegisterStart = channel.receive().await?;

    // Get server key for OPAQUE
    let server_setup = {
        let mut rng = context.rng.lock().await;

        create_or_retrieve_server_key_opaque(&mut rng, &context.service)?
    };

    // Abort registration if UserId already exists
    let user = User::find_user(&context.db, &start_message.user_id).await?;

    if user.is_some() {
        Err(DamsServerError::UserIdAlreadyExists)
    } else {
        // Registration can continue if user ID doesn't exist yet
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            start_message.registration_request,
            start_message.user_id.as_bytes(),
        )?;

        let reply = server::RegisterStart {
            registration_response: server_registration_start_result.message,
        };

        // Send response to client
        channel.send(reply).await?;

        Ok(())
    }
}

async fn register_finish(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    // Receive finish message from client
    let finish_message: client::RegisterFinish = channel.receive().await?;

    // run the finish step for OPAQUE
    let server_registration =
        ServerRegistration::<OpaqueCipherSuite>::finish(finish_message.registration_upload);

    // add the new user to the DB
    let _object_id =
        User::create_user(&context.db, &finish_message.user_id, server_registration).await?;

    // reply with the success:true if successful
    let reply = server::RegisterFinish { success: true };

    // Send response to client
    channel.send(reply).await?;

    Ok(())
}
