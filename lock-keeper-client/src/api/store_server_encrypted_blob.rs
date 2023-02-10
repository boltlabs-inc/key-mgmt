use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::KeyId,
    types::operations::store_server_encrypted_blob::{client, server},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_store_server_encrypted_blob(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        data_blob: Vec<u8>,
    ) -> Result<KeyId, LockKeeperClientError> {
        // Send data blob to server.
        channel.send(client::Request { data_blob }).await?;

        // Get Key ID from server.
        let server_response: server::Response = channel.receive().await?;
        Ok(server_response.key_id)
    }
}
