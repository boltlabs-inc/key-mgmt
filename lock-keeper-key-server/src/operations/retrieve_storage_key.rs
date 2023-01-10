use crate::{
    database::DataStore,
    server::{Context, Operation},
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::retrieve_storage_key::server,
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveStorageKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RetrieveStorageKey {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve storage key protocol.");
        let user_id = channel
            .metadata()
            .user_id()
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        // Find user by user ID.
        let user = context
            .db
            .find_account_by_id(user_id)
            .await
            .map_err(LockKeeperServerError::database)?
            .ok_or(LockKeeperServerError::InvalidAccount)?;

        // Send storage key if set
        let storage_key = user
            .storage_key
            .ok_or(LockKeeperServerError::StorageKeyNotSet)?;
        let reply = server::Response {
            ciphertext: storage_key,
        };
        channel.send(reply).await?;

        info!("Successfully completed retrieve protocol.");
        Ok(())
    }
}
