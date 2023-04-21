use crate::{
    error::LockKeeperServerError,
    server::{
        channel::{Channel, Unauthenticated},
        Context, Operation,
    },
};
use std::ops::DerefMut;

use crate::server::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    infrastructure::logging,
    types::{
        audit_event::EventStatus,
        database::account::{AccountName, UserId},
        operations::{
            register::{client, server},
            ClientAction,
        },
    },
};
use opaque_ke::ServerRegistration;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct Register;

#[async_trait]
impl<DB: DataStore> Operation<Unauthenticated, DB> for Register {
    #[instrument(skip_all, err(Debug), fields(account_name))]
    async fn operation(
        self,
        channel: &mut Channel<Unauthenticated>,
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
    channel: &mut Channel<Unauthenticated>,
    context: &Context<DB>,
) -> Result<AccountName, LockKeeperServerError> {
    // Receive start message from client
    let start_message: client::RegisterStart = channel.receive().await?;

    // Abort registration if UserId already exists
    let user = context
        .db
        .find_account_by_name(&start_message.account_name)
        .await?;

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

#[instrument(skip(channel, context), err(Debug))]
async fn register_finish<DB: DataStore>(
    account_name: &AccountName,
    channel: &mut Channel<Unauthenticated>,
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

        let user_id_exists = context.db.user_id_exists(&user_id).await?;

        if !user_id_exists {
            info!("Fresh user id generated: {:?}", user_id);
            let account = context
                .db
                .create_account(&user_id, account_name, &server_registration)
                .await?;
            let account_id = account.id();
            let request_id = channel.metadata().request_id();

            context
                .create_audit_event(
                    account_id,
                    request_id,
                    ClientAction::Register,
                    EventStatus::Successful,
                )
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
