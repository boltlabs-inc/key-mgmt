use crate::{
    database::log::AuditLogExt,
    server::{Context, Operation},
    DamsServerError,
};

use async_trait::async_trait;
use dams::{
    channel::ServerChannel,
    types::retrieve::{client, server},
    ClientAction,
};

#[derive(Debug)]
pub struct Retrieve;

#[async_trait]
impl Operation for Retrieve {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: Context,
    ) -> Result<(), DamsServerError> {
        // Receive UserId from client
        let request: client::Request = channel.receive().await?;

        // TODO #232: move this log so that we log the entire operation
        // Find secret based on key_id
        let stored_secret = context
            .db
            .get_user_secret(&request.user_id, &request.key_id)
            .await
            .audit_log(
                &context.db,
                &request.user_id,
                Some(request.key_id),
                ClientAction::Retrieve,
            )
            .await?;

        // Serialize KeyId and send to client
        let reply = server::Response { stored_secret };
        channel.send(reply).await?;
        Ok(())
    }
}
