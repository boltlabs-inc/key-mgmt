use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::{Import, KeyId},
    infrastructure::channel::ClientChannel,
    types::operations::import_signing_key::{client, server},
};

impl LockKeeperClient {
    pub(crate) async fn handle_import_signing_key(
        &self,
        channel: &mut ClientChannel,
        key_material: Vec<u8>,
    ) -> Result<KeyId, LockKeeperClientError> {
        let key_material = Import {
            material: key_material,
        };
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
