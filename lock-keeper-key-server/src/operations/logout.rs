use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::operations::logout::{client, server},
};

#[derive(Debug)]
pub struct Logout;

#[async_trait]
impl<DB: DataStore> Operation<DB> for Logout {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        // Receive UserId from client
        let request: client::Request = channel.receive().await?;

        // Expire the user's session key
        {
            context
                .session_key_cache
                .lock()
                .await
                .expire(request.user_id)?;
        }

        let reply = server::Response { success: true };
        channel.send(reply).await?;
        Ok(())
    }
}
