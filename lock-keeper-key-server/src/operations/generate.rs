use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::{
    channel::ServerChannel,
    crypto::KeyId,
    types::generate::{client, server},
};

#[derive(Debug)]
pub struct Generate;

#[async_trait]
impl Operation for Generate {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<(), LockKeeperServerError> {
        // Generate step: receive UserId and reply with new KeyId
        let key_id = generate_key(channel, context).await?;
        context.key_id = Some(key_id.clone());

        // Store step: receive ciphertext from client and store in DB
        store_key(channel, context, &key_id).await?;
        Ok(())
    }
}

async fn generate_key(
    channel: &mut ServerChannel,
    context: &Context,
) -> Result<KeyId, LockKeeperServerError> {
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
    Ok(key_id)
}

async fn store_key(
    channel: &mut ServerChannel,
    context: &Context,
    key_id: &KeyId,
) -> Result<(), LockKeeperServerError> {
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

    Ok(())
}
