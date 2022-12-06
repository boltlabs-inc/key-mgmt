use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    crypto::{KeyId, PlaceholderEncryptedSigningKeyPair},
    infrastructure::channel::ServerChannel,
    types::{
        database::secrets::StoredSecret,
        operations::import::{client, server},
    },
};
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct ImportSigningKey;

#[async_trait]
impl<DB: DataStore> Operation<DB> for ImportSigningKey {
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
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

        let secret = StoredSecret::from_remote_signing_key_pair(
            key_id.clone(),
            PlaceholderEncryptedSigningKeyPair::from(signing_key),
        )?;

        // Check validity of ciphertext and store in DB
        context
            .db
            .add_user_secret(&request.user_id, secret)
            .await
            .map_err(LockKeeperServerError::database)?;

        // Serialize KeyId and send to client
        let reply = server::Response { key_id };
        channel.send(reply).await?;
        Ok(())
    }
}
