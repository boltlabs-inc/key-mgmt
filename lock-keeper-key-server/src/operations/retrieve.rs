use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::operations::retrieve::{client, server},
};

#[derive(Debug)]
pub struct Retrieve;

#[async_trait]
impl<DB: DataStore> Operation<DB> for Retrieve {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        // Receive UserId from client
        let request: client::Request = channel.receive().await?;
        context.key_id = Some(request.key_id.clone());

        // Find secret based on key_id
        let stored_secret = context
            .db
            .get_user_secret(&request.user_id, &request.key_id)
            .await
            .map_err(LockKeeperServerError::database)?;

        // Serialize KeyId and send to client
        let reply = server::Response { stored_secret };
        channel.send(reply).await?;
        Ok(())
    }
}
