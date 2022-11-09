use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};
use std::ops::DerefMut;

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    infrastructure::channel::ServerChannel,
    types::{
        database::user::{AccountName, UserId},
        operations::register::{client, server},
    },
};
use opaque_ke::ServerRegistration;

#[derive(Debug)]
pub struct Register;

#[async_trait]
impl<DB: DataStore> Operation<DB> for Register {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        let account_name = register_start(channel, context).await?;
        register_finish(&account_name, channel, context).await?;

        Ok(())
    }
}

async fn register_start<DB: DataStore>(
    channel: &mut ServerChannel,
    context: &Context<DB>,
) -> Result<AccountName, LockKeeperServerError> {
    // Receive start message from client
    let start_message: client::RegisterStart = channel.receive().await?;

    // Abort registration if UserId already exists
    let user = context
        .db
        .find_user(&start_message.account_name)
        .await
        .map_err(LockKeeperServerError::database)?;

    if user.is_some() {
        Err(LockKeeperServerError::AccountAlreadyRegistered)
    } else {
        // Registration can continue if user ID doesn't exist yet
        let server_registration_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &context.config.opaque_server_setup,
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

async fn register_finish<DB: DataStore>(
    account_name: &AccountName,
    channel: &mut ServerChannel,
    context: &Context<DB>,
) -> Result<(), LockKeeperServerError> {
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
        if context
            .db
            .find_user_by_id(&user_id)
            .await
            .map_err(LockKeeperServerError::database)?
            .is_none()
        {
            let _user = context
                .db
                .create_user(&user_id, account_name, &server_registration)
                .await
                .map_err(LockKeeperServerError::database)?;
            break;
        }
    }

    // reply with the success:true if successful
    let reply = server::RegisterFinish { success: true };

    // Send response to client
    channel.send(reply).await?;

    Ok(())
}
