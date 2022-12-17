//! This operation allows client to specify a key ID for a key that was remotely
//! generated on the server and use this key to sign a message.
use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;

use lock_keeper::{
    crypto::{Encrypted, Signable, SigningKeyPair},
    infrastructure::channel::{Authenticated, ServerChannel},
    types::operations::remote_sign_bytes::{client, server},
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RemoteSignBytes;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RemoteSignBytes {
    /// Remotely sign protocol:
    /// 1) Receive remote sign request from client.
    /// 2) Look up signing key based on client-provided key ID.
    /// 3) Use signing key to sign client-provided data.
    /// 4) Respond to client with signed data, the signature.
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting remote sign protocol.");
        let request: client::RequestRemoteSign = channel.receive().await?;
        let encrypted_key: Encrypted<SigningKeyPair> = context
            .db
            .get_user_secret(&request.user_id, &request.key_id, Default::default())
            .await
            .map_err(LockKeeperServerError::database)?
            .try_into()?;
        info!("Signing key found. Signing...");

        let key = encrypted_key.decrypt_signing_key_by_server(
            &context.config.remote_storage_key,
            request.user_id,
            request.key_id,
        )?;

        let signature = request.data.sign(&key);
        let response = server::ReturnSignature { signature };
        channel.send(response).await?;

        info!("Successfully completed remote sign protocol.");
        Ok(())
    }
}
