use crate::{LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use lock_keeper::{
    crypto::{KeyId, SigningPublicKey},
    infrastructure::channel::ClientChannel,
    types::operations::remote_generate::{client, server},
};
use serde::{Deserialize, Serialize};

impl LockKeeperClient {
    pub(crate) async fn handle_remote_generate(
        &self,
        mut channel: ClientChannel,
    ) -> Result<LockKeeperResponse<RemoteGenerateResult>, LockKeeperClientError> {
        let request = client::RequestRemoteGenerate {
            user_id: self.user_id().clone(),
        };

        channel.send(request).await?;

        let response: server::ReturnKeyId = channel.receive().await?;
        let result = RemoteGenerateResult {
            key_id: response.key_id,
            public_key: response.public_key,
        };

        Ok(LockKeeperResponse::from_channel(channel, result))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteGenerateResult {
    pub key_id: KeyId,
    pub public_key: SigningPublicKey,
}
