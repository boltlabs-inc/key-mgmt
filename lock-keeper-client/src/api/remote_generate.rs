use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::KeyId,
    infrastructure::channel::ClientChannel,
    types::operations::remote_generate::{client, server},
};

impl LockKeeperClient {
    pub(crate) async fn handle_remote_generate(
        &self,
        channel: &mut ClientChannel,
    ) -> Result<KeyId, LockKeeperClientError> {
        let request = client::RequestRemoteGenerate {
            user_id: self.user_id().clone(),
        };

        channel.send(request).await?;

        let response: server::ReturnKeyId = channel.receive().await?;

        Ok(response.key_id)
    }
}
