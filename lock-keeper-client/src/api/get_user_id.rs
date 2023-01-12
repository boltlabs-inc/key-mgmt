use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::types::{database::account::UserId, operations::get_user_id::server};

use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_get_user_id(
        mut channel: Channel<Authenticated<StdRng>>,
    ) -> Result<UserId, LockKeeperClientError> {
        let response: server::Response = channel.receive().await?;
        Ok(response.user_id)
    }
}
