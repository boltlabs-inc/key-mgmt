use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::{Import, KeyId},
    infrastructure::channel::{Authenticated, ClientChannel},
    types::operations::import::{client, server},
};
use rand::rngs::StdRng;

impl LockKeeperClient {
    pub(crate) async fn handle_import_signing_key(
        &self,
        mut channel: ClientChannel<Authenticated<StdRng>>,
        key_material: Import,
    ) -> Result<KeyId, LockKeeperClientError> {
        // Send UserId and key material to server
        let request = client::Request {
            user_id: self.user_id().clone(),
            key_material,
        };
        channel.send(request).await?;

        // Get KeyId for imported key from server
        let server_response: server::Response = channel.receive().await?;
        Ok(server_response.key_id)
    }
}
