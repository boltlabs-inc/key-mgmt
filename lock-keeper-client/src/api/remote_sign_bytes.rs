use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::{KeyId, Signable, SignableBytes, Signature},
    types::operations::remote_sign_bytes::{client, server},
};
use rand::rngs::StdRng;

impl<T> LockKeeperClient<T> {
    pub(crate) async fn handle_remote_sign_bytes(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        key_id: KeyId,
        bytes: impl Signable,
    ) -> Result<Signature, LockKeeperClientError> {
        let request = client::RequestRemoteSign {
            key_id,
            data: SignableBytes(bytes.as_ref().to_vec()),
        };

        channel.send(request).await?;

        let response: server::ReturnSignature = channel.receive().await?;

        Ok(response.signature)
    }
}
