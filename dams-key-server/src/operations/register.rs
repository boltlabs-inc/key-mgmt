use crate::{
    database::log::AuditLogExt,
    error::DamsServerError,
    server::{Context, Operation},
};
use std::ops::DerefMut;

use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    config::opaque::OpaqueCipherSuite,
    opaque_storage::create_or_retrieve_server_key_opaque,
    types::register::{client, server},
    user::{AccountName, UserId},
    ClientAction,
};
use opaque_ke::ServerRegistration;

#[derive(Debug)]
pub struct Register;

#[async_trait]
impl Operation for Register {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        let account_name = register_start(channel, &context).await?;
        register_finish(&account_name, channel, &context)
            .await
            .audit_log(&context.db, &account_name, None, ClientAction::Register)
            .await?;

        Ok(())
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
    let user = context.db.find_user(&start_message.account_name).await?;

    if user.is_some() {
        Err(DamsServerError::AccountAlreadyRegistered)
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
        if context.db.find_user_by_id(&user_id).await?.is_none() {
            let _object_id = context
                .db
                .create_user(&user_id, account_name, &server_registration)
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
