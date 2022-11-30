use crate::{
    database::SecretFilter,
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::ServerChannel,
    types::operations::retrieve_secret::{client, server},
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveSecret;

#[async_trait]
impl<DB: DataStore> Operation<DB> for RetrieveSecret {
    /// Retrieve a stored secret from server.
    /// 1) Receive request from client
    /// 2) Find stored key in database.
    /// 3) Reply to client with stored key.
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve secret protocol.");
        // Receive UserId from client
        let request: client::Request = channel.receive().await?;
        context.key_id = Some(request.key_id.clone());

        // Find secret based on key_id
        let stored_secret = match request.secret_type {
            Some(secret_type) => context
                .db
                .get_user_secret(
                    &request.user_id,
                    &request.key_id,
                    SecretFilter::secret_type(secret_type),
                )
                .await
                .map_err(LockKeeperServerError::database)?,
            None => context
                .db
                .get_user_secret(&request.user_id, &request.key_id, Default::default())
                .await
                .map_err(LockKeeperServerError::database)?,
        };

        let reply = server::Response {
            secret: stored_secret,
        };
        channel.send(reply).await?;
        info!("Successfully completed retrieve secret protocol.");
        Ok(())
    }
}
