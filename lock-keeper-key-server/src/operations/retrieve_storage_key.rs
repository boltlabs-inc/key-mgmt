use crate::{
    server::{
        channel::{Authenticated, Channel},
        database::DataStore,
        Context, Operation,
    },
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{infrastructure::logging, types::operations::retrieve_storage_key::server};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RetrieveStorageKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RetrieveStorageKey {
    #[instrument(skip_all, err(Debug), fields(account_id))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        _context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting retrieve storage key protocol.");
        let account_id = channel.account_id();
        logging::record_field("account_id", &account_id);

        // Send storage key if set
        let storage_key = channel
            .account()
            .storage_key
            .clone()
            .ok_or(LockKeeperServerError::StorageKeyNotSet)?;

        let reply = server::Response {
            ciphertext: storage_key,
        };
        channel.send(reply).await?;

        info!("Successfully completed retrieve protocol.");
        Ok(())
    }
}
