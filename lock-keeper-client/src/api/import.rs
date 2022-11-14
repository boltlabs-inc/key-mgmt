use crate::{LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use lock_keeper::{
    crypto::{Import, KeyId},
    infrastructure::channel::ClientChannel,
    types::operations::import::{client, server},
};

impl LockKeeperClient {
    pub(crate) async fn handle_import_signing_key(
        &self,
        mut channel: ClientChannel,
        key_material: Vec<u8>,
    ) -> Result<LockKeeperResponse<KeyId>, LockKeeperClientError> {
        let key_material = Import { key_material };
        // Send UserId and key material to server
        let request = client::Request {
            user_id: self.user_id().clone(),
            key_material,
        };
        channel.send(request).await?;

        // Get KeyId for imported key from server
        let server_response: server::Response = channel.receive().await?;

        Ok(LockKeeperResponse::from_channel(
            channel,
            server_response.key_id,
        ))
    }
}
