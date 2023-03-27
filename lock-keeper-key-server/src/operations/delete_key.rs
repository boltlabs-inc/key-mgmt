use crate::{
    server::{
        channel::{Authenticated, Channel},
        database::DataStore,
        Context, Operation,
    },
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::types::operations::delete_key::{client, server};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct DeleteKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for DeleteKey {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting delete key protocol.");
        let request: client::Request = channel.receive().await?;
        // We cannot inline this expression, or Rust will complain about holding
        // references across `await` in a future.
        let account_id = channel.account_id();
        context.key_id = Some(request.key_id.clone());

        context
            .db
            .delete_secret(account_id, &request.key_id)
            .await?;

        channel.send(server::Response { success: true }).await?;

        info!("Successfully completed delete key protocol.");
        Ok(())
    }
}
