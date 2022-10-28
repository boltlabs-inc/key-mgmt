use crate::{LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::{KeyId, Signable, SignableBytes, Signature},
    infrastructure::channel::ClientChannel,
    types::operations::remote_sign_bytes::{client, server},
};

impl LockKeeperClient {
    pub(crate) async fn handle_remote_sign_bytes(
        &self,
        channel: &mut ClientChannel,
        key_id: KeyId,
        bytes: impl Signable,
    ) -> Result<Signature, LockKeeperClientError> {
        let request = client::RequestRemoteSign {
            user_id: self.user_id().clone(),
            key_id,
            data: SignableBytes(bytes.as_ref().to_vec()),
        };

        channel.send(request).await?;

        let response: server::ReturnSignature = channel.receive().await?;

        Ok(response.signature)
    }
}
