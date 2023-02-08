use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::KeyId,
    types::operations::retrieve_server_encrypted_blob::{client, server},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_retrieve_server_encrypted_blob(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_id: &KeyId,
    ) -> Result<Vec<u8>, LockKeeperClientError> {
        // Send data blob to server.
        channel
            .send(client::Request {
                key_id: key_id.clone(),
            })
            .await?;

        // Get Key ID from server.
        let server_response: server::Response = channel.receive().await?;
        Ok(server_response.data_blob)
    }
}
