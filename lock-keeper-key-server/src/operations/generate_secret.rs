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
        operations::generate::{client, server},
    },
};
use rand::rngs::StdRng;
use tracing::{info, instrument};

#[derive(Debug)]
pub struct GenerateSecret;

#[async_trait]
impl<DB: DataStore> Operation<Authenticated<StdRng>, DB> for GenerateSecret {
    /// Client will:
    /// 1) Create and encrypt an arbitrary secret entirely on the client-side.
    /// 2) Send the server the encrypted secret.
    /// Server will:
    /// 1) Receive this encrypted secret.
    /// 2) Generate a new key_id and send it back to client.
    /// 3) Store encrypted secret in our persistent storage as an arbitrary
    /// secret.
    ///
    /// Client may use key_id to refer to this stored secret.
    #[instrument(skip_all, err(Debug))]
    async fn operation(
        self,
        channel: &mut Channel<Authenticated<StdRng>>,
        context: &mut Context<DB>,
    ) -> Result<(), LockKeeperServerError> {
        info!("Starting generate protocol");
        // Generate step: receive UserId and reply with new KeyId
        let key_id = generate_key_id(channel, context).await?;
        context.key_id = Some(key_id.clone());

        // Store step: receive ciphertext from client and store in DB
        store_key(channel, context, &key_id).await?;
        info!("Successfully completed generate protocol.");
        Ok(())
    }
}

/// First step for generation:
/// 1) Generate a new key ID.
/// 2) Send generated Key ID as a response to client via channel.
///
/// Returns generated key_id.
#[instrument(skip_all, err(Debug))]
async fn generate_key_id<DB: DataStore>(
    channel: &mut Channel<Authenticated<StdRng>>,
    context: &Context<DB>,
) -> Result<KeyId, LockKeeperServerError> {
    let user_id = channel.user_id();

    // Generate new KeyId
    let key_id = {
        let mut rng = context.rng.lock().await;
        KeyId::generate(&mut *rng, user_id)?
    };
    info!("New key_id generated: {:?}", key_id);

    // Serialize KeyId and send to client
    let reply = server::Generate {
        key_id: key_id.clone(),
    };
    channel.send(reply).await?;
    Ok(key_id)
}

/// Second step for generation operation.
/// 1) Receive store message from client.
/// 2) Check validity of ciphertext and store in DB.
/// 3) Reply to client if successful.
#[instrument(skip_all, err(Debug))]
async fn store_key<DB: DataStore>(
    channel: &mut Channel<Authenticated<StdRng>>,
    context: &Context<DB>,
    key_id: &KeyId,
) -> Result<(), LockKeeperServerError> {
    // Receive Encrypted<Secret> from client
    let store_message: client::Store = channel.receive().await?;

    // Transform client's secret into arbitrary_secret and store.
    let secret = StoredSecret::from_arbitrary_secret(
        key_id.clone(),
        channel.account_id(),
        store_message.ciphertext,
    )?;
    context.db.add_secret(secret).await?;
    info!("Client's cypher text stored successfully.");

    // Reply with the success:true if successful
    let reply = server::Store { success: true };
    channel.send(reply).await?;

    Ok(())
}
