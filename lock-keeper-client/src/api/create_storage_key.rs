use crate::{client::LockKeeperClient, LockKeeperClientError};
use lock_keeper::{
    channel::ClientChannel,
    crypto::OpaqueExportKey,
    types::create_storage_key::{client, server},
    user::{AccountName, UserId},
};
use rand::{CryptoRng, RngCore};

impl LockKeeperClient {
    /// Creates a storage key and sends it to the key server
    pub(crate) async fn handle_create_storage_key<T: CryptoRng + RngCore>(
        mut channel: ClientChannel,
        rng: &mut T,
        account_name: &AccountName,
        export_key: OpaqueExportKey,
    ) -> Result<(), LockKeeperClientError> {
        let user_id = request_user_id(&mut channel, account_name).await?;
        create_and_send_storage_key(&mut channel, rng, user_id, export_key).await?;

        Ok(())
    }
}

async fn request_user_id(
    channel: &mut ClientChannel,
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
    channel: &mut ClientChannel,
    rng: &mut T,
    user_id: UserId,
    export_key: OpaqueExportKey,
) -> Result<(), LockKeeperClientError> {
    let storage_key = export_key.create_and_encrypt_storage_key(rng, &user_id)?;

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
