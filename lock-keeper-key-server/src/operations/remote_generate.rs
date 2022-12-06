use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    crypto::{KeyId, SigningKeyPair},
    infrastructure::channel::ServerChannel,
    types::operations::remote_generate::{client, server},
};
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct RemoteGenerate;

#[async_trait]
impl<DB: DataStore> Operation<DB> for RemoteGenerate {
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        let request: client::RequestRemoteGenerate = channel.receive().await?;

        // Create a scope for rng mutex
        let (key_id, key_pair) = {
            let mut rng = context.rng.lock().await;
            let key_id = KeyId::generate(&mut *rng, &request.user_id)?;
            let key_pair = SigningKeyPair::remote_generate(&mut *rng, &request.user_id, &key_id);

            (key_id, key_pair)
        };

        let public_key = key_pair.public_key();

        // Store key in database
        context
            .db
            .add_remote_secret(&request.user_id, key_pair, key_id.clone())
            .await
            .map_err(LockKeeperServerError::database)?;

        let response = server::ReturnKeyId { key_id, public_key };

        channel.send(response).await?;

        Ok(())
    }
}
