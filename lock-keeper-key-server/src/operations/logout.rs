use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::{database::DataStore, server::session_cache::SessionCacheError};
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::logout::server,
};
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct Logout;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for Logout {
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        // Receive UserId from client
        let session_id = channel
            .metadata()
            .session_id()
            .ok_or(SessionCacheError::MissingSession)?;

        // Expire the user's session key
        {
            context
                .session_cache
                .lock()
                .await
                .delete_session(session_id.clone())
                .await?;
        }

        let reply = server::Response { success: true };
        channel.send(reply).await?;
        Ok(())
    }
}
