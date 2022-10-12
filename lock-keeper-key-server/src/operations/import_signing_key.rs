use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::{
    crypto::KeyId,
    infrastructure::channel::ServerChannel,
    types::operations::import_signing_key::{client, server},
};

#[derive(Debug)]
pub struct ImportSigningKey;

#[async_trait]
impl Operation for ImportSigningKey {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<(), LockKeeperServerError> {
        // Receive UserId and key material from client
        let request: client::Request = channel.receive().await?;

        // Generate new KeyId
        let key_id = {
            let mut rng = context.rng.lock().await;
            KeyId::generate(&mut *rng, &request.user_id)?
        };
        context.key_id = Some(key_id.clone());

        // Make signing key out of bytes
        let signing_key = request
            .key_material
            .into_signing_key(&request.user_id, &key_id)?;

        // Check validity of ciphertext and store in DB
        context
            .db
            .add_server_imported_signing_key(&request.user_id, signing_key, key_id.clone())
            .await?;

        // Serialize KeyId and send to client
        let reply = server::Response { key_id };
        channel.send(reply).await?;
        Ok(())
    }
}
