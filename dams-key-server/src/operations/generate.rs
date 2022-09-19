use crate::{
    database::log::AuditLogExt,
    server::{Context, Operation},
    DamsServerError,
};

use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    crypto::KeyId,
    types::generate::{client, server},
    user::UserId,
    ClientAction,
};

#[derive(Debug)]
pub struct Generate;

#[async_trait]
impl Operation for Generate {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        // Generate step: receive UserId and reply with new KeyId
        let (key_id, user_id) = generate_key(channel, &context).await?;

        // Store step: receive ciphertext from client and store in DB
        store_key(channel, &context, &key_id)
            .await
            .audit_log(&context.db, &user_id, Some(key_id), ClientAction::Generate)
            .await?;
        Ok(())
    }
}

async fn generate_key(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<(KeyId, UserId), DamsServerError> {
    // Receive UserId from client
    let generate_message: client::Generate = channel.receive().await?;
    // Generate new KeyId
    let key_id = {
        let mut rng = context.rng.lock().await;
        KeyId::generate(&mut *rng, &generate_message.user_id)?
    };
    // Serialize KeyId and send to client
    let reply = server::Generate {
        key_id: key_id.clone(),
    };
    channel.send(reply).await?;
    Ok((key_id, generate_message.user_id))
}

async fn store_key(
    channel: &mut ServerChannel,
    context: &Context,
    key_id: &KeyId,
) -> Result<(), DamsServerError> {
    // Receive Encrypted<Secret> from client
    let store_message: client::Store = channel.receive().await?;

    // Check validity of ciphertext and store in DB
    context
        .db
        .add_user_secret(
            &store_message.user_id,
            store_message.ciphertext,
            key_id.clone(),
        )
        .await?;

    // Reply with the success:true if successful
    let reply = server::Store { success: true };
    channel.send(reply).await?;

    // TODO #67 (implementation): Log that a new key was generated and stored

    Ok(())
}
