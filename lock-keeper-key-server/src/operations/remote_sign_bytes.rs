use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use async_trait::async_trait;
use lock_keeper::{
    crypto::{Signable, SigningKeyPair},
    infrastructure::channel::ServerChannel,
    types::operations::remote_sign_bytes::{client, server},
};

#[derive(Debug)]
pub struct RemoteSignBytes;

#[async_trait]
impl Operation for RemoteSignBytes {
    async fn operation(
        self,
        channel: &mut ServerChannel,
        context: &mut Context,
    ) -> Result<(), LockKeeperServerError> {
        let request: client::RequestRemoteSign = channel.receive().await?;
        let key: SigningKeyPair = context
            .db
            .get_user_signing_key(&request.user_id, &request.key_id)
            .await?
            .signing_key
            .try_into()?;

        let signature = request.data.sign(&key);

        let response = server::ReturnSignature { signature };
        channel.send(response).await?;

        Ok(())
    }
}
