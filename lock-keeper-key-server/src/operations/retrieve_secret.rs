use crate::{
    server::{
        channel::{Authenticated, Channel},
        database::{DataStore, SecretFilter},
        Context, Operation,
    },
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::types::operations::retrieve_secret::{client, server, RetrievedSecret};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveSecret;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RetrieveSecret {
    /// Retrieve a stored secret from server.
    /// 1) Receive request from client
    /// 2) Find stored key in database.
    /// 3) Reply to client with stored key.
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve secret protocol.");
        let request: client::Request = channel.receive().await?;

        context.key_id = Some(request.key_id.clone());

        let secret_filter = request
            .secret_type
            .map_or_else(Default::default, SecretFilter::secret_type);

        let account_id = channel.account_id();

        // Find secret based on key_id
        let stored_secret = context
            .db
            .get_secret(account_id, &request.key_id, secret_filter)
            .await?;

        let user_id = channel.user_id().clone();

        let reply = server::Response {
            secret: RetrievedSecret::try_from_stored_secret(
                stored_secret,
                user_id,
                context.config.remote_storage_key.clone(),
            )?,
        };
        channel.send(reply).await?;
        info!("Successfully completed retrieve secret protocol.");
        Ok(())
    }
}
