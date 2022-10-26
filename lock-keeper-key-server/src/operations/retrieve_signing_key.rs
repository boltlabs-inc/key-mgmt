use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::operations::retrieve::{client, server},
};

#[derive(Debug)]
pub struct RetrieveSigningKey;

#[async_trait]
impl Operation for RetrieveSigningKey {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<(), LockKeeperServerError> {
        // Receive UserId from client
        let request: client::RequestSigningKey = channel.receive().await?;
        context.key_id = Some(request.key_id.clone());

        // Find secret based on key_id
        let stored_signing_key = context
            .db
            .get_user_signing_key(&request.user_id, &request.key_id)
            .await?;

        // Send StoredSigningKeyPair back
        let reply = server::ResponseSigningKey { stored_signing_key };
        channel.send(reply).await?;
        Ok(())
    }
}
