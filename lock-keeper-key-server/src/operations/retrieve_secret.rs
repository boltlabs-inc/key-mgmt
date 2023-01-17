use crate::{
    database::SecretFilter,
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::retrieve_secret::{client, server, RetrievedSecret},
};
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
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve secret protocol.");
        let request: client::Request = channel.receive().await?;
        let user_id = channel
            .metadata()
            .user_id()
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        context.key_id = Some(request.key_id.clone());

        let secret_filter = request
            .secret_type
            .map_or_else(Default::default, SecretFilter::secret_type);

        // Find secret based on key_id
        let stored_secret = context
            .db
            .get_secret(user_id, &request.key_id, secret_filter)
            .await?;

        let reply = server::Response {
            secret: RetrievedSecret::try_from_stored_secret(
                stored_secret,
                user_id.clone(),
                context.config.remote_storage_key.clone(),
            )?,
        };
        channel.send(reply).await?;
        info!("Successfully completed retrieve secret protocol.");
        Ok(())
    }
}
