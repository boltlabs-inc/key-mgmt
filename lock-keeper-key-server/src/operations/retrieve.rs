use crate::{
    server::{Context, Operation, OperationResult},
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::{
    channel::ServerChannel,
    types::retrieve::{client, server},
};

#[derive(Debug)]
pub struct Retrieve;

#[async_trait]
impl Operation for Retrieve {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<OperationResult, LockKeeperServerError> {
        // Receive UserId from client
        let request: client::Request = channel.receive().await?;
        context.key_id = Some(request.key_id.clone());

        // Find secret based on key_id
        let stored_secret = context
            .db
            .get_user_secret(&request.user_id, &request.key_id)
            .await?;

        // Serialize KeyId and send to client
        let reply = server::Response { stored_secret };
        channel.send(reply).await?;
        Ok(OperationResult(Some(request.key_id)))
    }
}
