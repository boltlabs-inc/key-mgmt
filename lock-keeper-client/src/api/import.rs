use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::{Import, KeyId},
    types::operations::import::{client, server},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_import_signing_key(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_material: Import,
    ) -> Result<KeyId, LockKeeperClientError> {
        // Send UserId and key material to server
        let request = client::Request { key_material };
        channel.send(request).await?;

        // Get KeyId for imported key from server
        let server_response: server::Response = channel.receive().await?;
        Ok(server_response.key_id)
    }
}
