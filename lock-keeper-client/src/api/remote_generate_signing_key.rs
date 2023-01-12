use crate::{
    channel::{Authenticated, Channel},
    LockKeeperClient, LockKeeperClientError,
};
use lock_keeper::{
    crypto::{KeyId, SigningPublicKey},
    types::operations::remote_generate::server,
};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};

impl LockKeeperClient {
    pub(crate) async fn handle_remote_generate_signing_key(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
    ) -> Result<RemoteGenerateResult, LockKeeperClientError> {
        let response: server::ReturnKeyId = channel.receive().await?;
        Ok(RemoteGenerateResult {
            key_id: response.key_id,
            public_key: response.public_key,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteGenerateResult {
    pub key_id: KeyId,
    pub public_key: SigningPublicKey,
}
