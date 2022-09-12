use crate::{database::user as User, error::DamsServerError, server::Context};
use std::ops::DerefMut;

use crate::error::LogExt;
use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::{
        register::{client, server},
        Message, MessageStream,
    },
    user::{AccountName, UserId},
    ClientAction,
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
            let account_name = register_start(&mut channel, &context).await?;
            register_finish(&account_name, &mut channel, &context)
                .await
                .log(
                    &context.db,
                    &account_name.into(),
                    None,
                    ClientAction::Register,
                )
                .await?;

            Ok::<(), DamsServerError>(())
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

async fn register_start(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<AccountName, DamsServerError> {
    // Receive start message from client
    let start_message: client::RegisterStart = channel.receive().await?;

    // Get server key for OPAQUE
    let server_setup = {
        let mut rng = context.rng.lock().await;

        create_or_retrieve_server_key_opaque(&mut rng, &context.service)?
    };

    // Abort registration if UserId already exists
    let user = User::find_user(&context.db, &start_message.account_name).await?;

    if user.is_some() {
        Err(DamsServerError::InvalidUserId)
    } else {
        // Registration can continue if user ID doesn't exist yet
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            start_message.registration_request,
            start_message.account_name.as_bytes(),
        )?;

        let reply = server::RegisterStart {
            registration_response: server_registration_start_result.message,
        };

        // Send response to client
        channel.send(reply).await?;

        Ok(start_message.account_name)
    }
}

async fn register_finish(
    account_name: &AccountName,
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(), DamsServerError> {
    // Receive finish message from client
    let finish_message: client::RegisterFinish = channel.receive().await?;

    // run the finish step for OPAQUE
    let server_registration =
        ServerRegistration::<OpaqueCipherSuite>::finish(finish_message.registration_upload);

    loop {
        // Create a user ID for the new client
        let user_id = {
            let mut rng = context.rng.lock().await;
            UserId::new(rng.deref_mut())?
        };

        // If the user ID is fresh, create the new user
        if User::find_user_by_id(&context.db, &user_id)
            .await?
            .is_none()
        {
            let _object_id =
                User::create_user(&context.db, &user_id, account_name, &server_registration)
                    .await?;
            break;
        }
    }

    // reply with the success:true if successful
    let reply = server::RegisterFinish { success: true };

    // Send response to client
    channel.send(reply).await?;

    Ok(())
}
