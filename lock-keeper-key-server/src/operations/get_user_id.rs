use crate::{
    error::LockKeeperServerError,
    server::{Context, Operation},
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::get_user_id::server,
};

use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct GetUserId;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for GetUserId {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        _context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting GetUserId protocol.");
        let user_id = channel
            .metadata()
            .user_id()
            .ok_or(LockKeeperServerError::InvalidAccount)?
            .clone();

        let response = server::Response { user_id };
        channel.send(response).await?;
        info!("Successfully completed GetUserId protocol.");
        Ok(())
    }
}
