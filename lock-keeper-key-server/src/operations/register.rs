use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};
use std::ops::DerefMut;

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    infrastructure::{channel::ServerChannel, logging},
    types::{
        database::user::{AccountName, UserId},
        operations::register::{client, server},
    },
};
use opaque_ke::ServerRegistration;
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct Register;

#[async_trait]
impl<DB: DataStore> Operation<DB> for Register {
    #[instrument(skip_all, err(Debug), fields(account_name))]
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting register protocol.");

        let account_name = register_start(channel, context).await?;
        logging::record_field("account_name", &account_name);

        register_finish(&account_name, channel, context).await?;
        info!("Successfully completed register protocol.");
        Ok(())
    }
}

#[instrument(skip_all, err(Debug), fields(user_id))]
async fn register_start<DB: DataStore>(
    channel: &mut ServerChannel<StdRng>,
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

    match user {
        // Abort registration if UserId already exists
        Some(user) => {
            logging::record_field("user_id", &user.user_id);
            Err(LockKeeperServerError::AccountAlreadyRegistered)
        }
        // Registration can continue if user ID doesn't exist yet
        None => {
            info!("Account name available for registration.");
            let registration_start = ServerRegistration::<OpaqueCipherSuite>::start(
                &context.config.opaque_server_setup,
                start_message.registration_request,
                start_message.account_name.as_bytes(),
            )?;

            let reply = server::RegisterStart {
                registration_response: registration_start.message,
            };

            // Send response to client
            channel.send(reply).await?;

            Ok(start_message.account_name)
        }
    }
}

#[instrument(skip_all, err(Debug))]
async fn register_finish<DB: DataStore>(
    account_name: &AccountName,
    channel: &mut ServerChannel<StdRng>,
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
            info!("Fresh user id generated: {:?}", user_id);
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
