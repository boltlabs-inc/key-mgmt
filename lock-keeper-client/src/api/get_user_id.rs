use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    infrastructure::channel::{Authenticated, ClientChannel},
    types::{database::user::UserId, operations::get_user_id::server},
};

use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_get_user_id(
        mut channel: ClientChannel<Authenticated<StdRng>>,
    ) -> Result<UserId, LockKeeperClientError> {
        let response: server::Response = channel.receive().await?;
        Ok(response.user_id)
    }
}
