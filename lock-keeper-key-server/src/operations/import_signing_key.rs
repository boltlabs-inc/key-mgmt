//! Import signing key operation. This protocol allows the client to import a
//! key into the server.
use crate::{
    server::{
        channel::{Authenticated, Channel},
        Context, Operation,
    },
    LockKeeperServerError,
};

use crate::server::database::DataStore;
use async_trait::async_trait;
use lock_keeper::{
    crypto::KeyId,
    types::{
        database::secrets::StoredSecret,
        operations::import::{client, server},
    },
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct ImportSigningKey;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for ImportSigningKey {
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting import key operation.");
        // Receive UserId and key material from client.
        let request: client::Request = channel.receive().await?;
        let user_id = channel.user_id();

        // Generate new KeyId
        let key_id = {
            let mut rng = context.rng.lock().await;
            KeyId::generate(&mut *rng, user_id)?
        };
        context.key_id = Some(key_id.clone());

        // Make signing key out of bytes
        let signing_key = request.key_material.into_signing_key(user_id, &key_id)?;

        // encrypt key_pair
        let encrypted_key_pair = {
            let mut rng = context.rng.lock().await;
            context
                .config
                .remote_storage_key
                .encrypt_signing_key_pair(&mut *rng, signing_key)?
        };

        let secret = StoredSecret::from_remote_signing_key_pair(
            key_id.clone(),
            encrypted_key_pair,
            channel.account_id(),
        )?;

        // Check validity of ciphertext and store in DB
        context.db.add_secret(secret).await?;

        // Serialize KeyId and send to client
        let reply = server::Response {
            key_id: key_id.clone(),
        };
        channel.send(reply).await?;

        info!(
            "Successfully completed import key protocol. For key: {:?}",
            key_id
        );
        Ok(())
    }
}
