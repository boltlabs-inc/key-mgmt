use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::KeyId,
    types::operations::delete_key::{client, server},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_delete_key(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_id: &KeyId,
    ) -> Result<(), LockKeeperClientError> {
        // Send key ID to server.
        channel
            .send(client::Request {
                key_id: key_id.clone(),
            })
            .await?;

        // Get Key ID from server.
        let server_response: server::Response = channel.receive().await?;
        if server_response.success {
            Ok(())
        } else {
            Err(LockKeeperClientError::DeleteKeyFailed)
        }
    }
}
