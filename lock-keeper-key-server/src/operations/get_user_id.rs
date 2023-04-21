use crate::{
    error::LockKeeperServerError,
    server::{
        channel::{Authenticated, Channel},
        Context, Operation,
    },
};

use crate::server::database::DataStore;
use async_trait::async_trait;
use lock_keeper::types::operations::get_user_id::server;

use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct GetUserId;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for GetUserId {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        _context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting GetUserId protocol.");
        let user_id = channel.user_id().clone();

        let response = server::Response { user_id };
        channel.send(response).await?;
        info!("Successfully completed GetUserId protocol.");
        Ok(())
    }
}
