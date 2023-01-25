use crate::{
    channel::{Authenticated, Channel},
    client::{LockKeeperClient, LockKeeperRpcClientInner},
    LockKeeperClientError,
};
use lock_keeper::{
    crypto::MasterKey,
    types::{
        database::account::UserId,
        operations::create_storage_key::{client, server},
    },
};
use rand::{rngs::StdRng, CryptoRng, RngCore};
use std::sync::Arc;
use tokio::sync::Mutex;

impl<T> LockKeeperClient<LockKeeperRpcClientInner<T>> {
    /// Creates a storage key and sends it to the key server
    pub(crate) async fn handle_create_storage_key<R: CryptoRng + RngCore>(
        &self,
        mut channel: Channel<Authenticated<StdRng>>,
        rng: Arc<Mutex<R>>,
        master_key: MasterKey,
    ) -> Result<(), LockKeeperClientError> {
        let user_id = self.user_id().clone();
        create_and_send_storage_key(&mut channel, rng, user_id, master_key).await?;

        Ok(())
    }
}

async fn create_and_send_storage_key<T: CryptoRng + RngCore>(
    channel: &mut Channel<Authenticated<StdRng>>,
    rng: Arc<Mutex<T>>,
    user_id: UserId,
    master_key: MasterKey,
) -> Result<(), LockKeeperClientError> {
    let storage_key = {
        let mut rng = rng.lock().await;
        master_key.create_and_encrypt_storage_key(&mut *rng, &user_id)?
    };

    let response = client::SendStorageKey { storage_key };
    channel.send(response).await?;

    let result: server::CreateStorageKeyResult = channel.receive().await?;

    if result.success {
        Ok(())
    } else {
        Err(LockKeeperClientError::ServerReturnedFailure)
    }
}
