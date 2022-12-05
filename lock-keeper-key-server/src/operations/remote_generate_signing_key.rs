//! Client has asked server to generate a new signing key and store it in the
//! server.
use crate::{
    server::{Context, Operation},
    LockKeeperServerError,
};

use crate::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    crypto::{KeyId, SigningKeyPair},
    infrastructure::channel::{Authenticated, ServerChannel},
    types::{
        database::secrets::StoredSecret,
        operations::remote_generate::{client, server},
    },
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct RemoteGenerateSigningKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for RemoteGenerateSigningKey {
    /// Remote generation protocol works as follows:
    /// 1) Receive remote generate message from client.
    /// 2) Generate key ID and new signing key pair (private and public key).
    /// 3) Store key pair in our database.
    /// 4) Reply to client with public key and key ID.
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut ServerChannel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting remote generate protocol.");
        let request: client::RequestRemoteGenerate = channel.receive().await?;

        // Create a scope for rng mutex
        let (key_id, key_pair) = {
            let mut rng = context.rng.lock().await;
            let key_id = KeyId::generate(&mut *rng, &request.user_id)?;
            let key_pair = SigningKeyPair::remote_generate(&mut *rng, &request.user_id, &key_id);
            info!("Generated key ID: {:?}", key_id);
            (key_id, key_pair)
        };

        let public_key = key_pair.public_key();

        // encrypt key_pair
        let encrypted_key_pair = {
            let mut rng = context.rng.lock().await;
            context
                .config
                .server_side_encryption_key
                .encrypt_signing_key_pair(&mut *rng, key_pair, &request.user_id, &key_id)?
        };

        let secret =
            StoredSecret::from_remote_signing_key_pair(key_id.clone(), encrypted_key_pair)?;

        // Store key in database
        context
            .db
            .add_user_secret(&request.user_id, secret)
            .await
            .map_err(LockKeeperServerError::database)?;

        channel
            .send(server::ReturnKeyId { key_id, public_key })
            .await?;

        info!("Successfully completed remote generate protocol.");
        Ok(())
    }
}
