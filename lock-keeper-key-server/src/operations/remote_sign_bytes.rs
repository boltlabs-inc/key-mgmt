use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    crypto::{PlaceholderEncryptedSigningKeyPair, Signable, SigningKeyPair},
    infrastructure::channel::ServerChannel,
    types::operations::remote_sign_bytes::{client, server},
};
use rand::rngs::StdRng;

#[derive(Debug)]
pub struct RemoteSignBytes;

#[async_trait]
impl<DB: DataStore> Operation<DB> for RemoteSignBytes {
    async fn operation(
        self,
        channel: &mut ServerChannel<StdRng>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        let request: client::RequestRemoteSign = channel.receive().await?;
        let key_pair: PlaceholderEncryptedSigningKeyPair = context
            .db
            .get_user_secret(&request.user_id, &request.key_id, Default::default())
            .await
            .map_err(LockKeeperServerError::database)?
            .try_into()?;

        // Pretend to decrypt our placeholder type
        let key: SigningKeyPair = key_pair.try_into()?;

        let signature = request.data.sign(&key);

        let response = server::ReturnSignature { signature };
        channel.send(response).await?;

        Ok(())
    }
}
