use crate::{client::LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    crypto::MasterKey,
    infrastructure::channel::ClientChannel,
    types::{
        database::user::{AccountName, UserId},
        operations::create_storage_key::{client, server},
    },
};
use rand::{rngs::StdRng, CryptoRng, RngCore};
use std::sync::Arc;
use tokio::sync::Mutex;

impl LockKeeperClient {
    /// Creates a storage key and sends it to the key server
    pub(crate) async fn handle_create_storage_key<T: CryptoRng + RngCore>(
        mut channel: ClientChannel<StdRng>,
        rng: Arc<Mutex<T>>,
        account_name: &AccountName,
        master_key: MasterKey,
    ) -> Result<(), LockKeeperClientError> {
        let user_id = request_user_id(&mut channel, account_name).await?;
        create_and_send_storage_key(&mut channel, rng, user_id, master_key).await?;

        Ok(())
    }
}

async fn request_user_id(
    channel: &mut ClientChannel<StdRng>,
    account_name: &AccountName,
) -> Result<UserId, LockKeeperClientError> {
    let response = client::RequestUserId {
        account_name: account_name.clone(),
    };

    channel.send(response).await?;
    let request_user_id_result: server::SendUserId = channel.receive().await?;

    Ok(request_user_id_result.user_id)
}

async fn create_and_send_storage_key<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel<StdRng>,
    rng: Arc<Mutex<T>>,
    user_id: UserId,
    master_key: MasterKey,
) -> Result<(), LockKeeperClientError> {
    let storage_key = {
        let mut rng = rng.lock().await;
        master_key.create_and_encrypt_storage_key(&mut *rng, &user_id)?
    };

    let response = client::SendStorageKey {
        user_id,
        storage_key,
    };
    channel.send(response).await?;

    let result: server::CreateStorageKeyResult = channel.receive().await?;

    if result.success {
        Ok(())
    } else {
        Err(LockKeeperClientError::ServerReturnedFailure)
    }
}
