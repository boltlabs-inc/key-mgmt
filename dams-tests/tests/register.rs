use std::str::FromStr;

use anyhow::Result;
use dams::{
    channel::ClientChannel, config::opaque::OpaqueCipherSuite, crypto::OpaqueExportKey,
    user::AccountName, ClientAction,
};
use dams_client::{client::Password, DamsClient};
use opaque_ke::ClientRegistration;
use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};

mod common;

#[tokio::test]
pub async fn test_storage_key_stored_correctly() -> Result<()> {
    use dams::types::create_storage_key::{client, server};

    let context = common::setup().await;

    let account_name = AccountName::from_str("testUser")?;
    let password = Password::from_str("testPassword")?;
    let config = context.client_config.clone();
    let mut rng = StdRng::from_entropy();
    let mut rpc_client = common::create_rpc_client(&config)?;

    // Register
    let register_channel =
        DamsClient::create_channel(&mut rpc_client, ClientAction::Register).await?;
    let export_key =
        handle_registration(register_channel, &mut rng, &account_name, &password).await?;

    // Authenticate
    let _ = DamsClient::authenticate(rpc_client.clone(), &account_name, &password, &config).await?;

    // Manually run through storage key creation so we can keep a copy of the
    // storage key to check later
    let mut create_sk_channel =
        DamsClient::create_channel(&mut rpc_client, ClientAction::CreateStorageKey).await?;

    // Request user id
    let request = client::RequestUserId {
        account_name: account_name.clone(),
    };
    create_sk_channel.send(request).await?;
    let user_id = create_sk_channel
        .receive::<server::SendUserId>()
        .await?
        .user_id;

    // Create storage key
    let storage_key = export_key.create_and_encrypt_storage_key(&mut rng, &user_id)?;

    // Send storage key back to server
    let response = client::SendStorageKey {
        user_id,
        storage_key: storage_key.clone(),
    };
    create_sk_channel.send(response).await?;
    let result: server::CreateStorageKeyResult = create_sk_channel.receive().await?;
    assert!(result.success);

    // Get user from database
    let user = context.database.find_user(&account_name).await?.unwrap();

    assert!(user.storage_key.is_some());
    let stored_storage_key = user.storage_key.unwrap();

    // Compare generated storage key to database value
    assert_eq!(storage_key, stored_storage_key);

    context.teardown().await;

    Ok(())
}

/// Reimplements this private function from [`DamsClient`].
/// This should not be part of the public interface for [`DamsClient`].
async fn handle_registration<T: CryptoRng + RngCore>(
    mut channel: ClientChannel,
    rng: &mut T,
    account_name: &AccountName,
    password: &Password,
) -> Result<OpaqueExportKey> {
    use dams::types::register::{client, server};

    let client_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes()).unwrap();

    let response = client::RegisterStart {
        registration_request: client_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(response).await?;

    let server_start_result: server::RegisterStart = channel.receive().await?;

    let client_finish_registration_result = client_start_result
        .state
        .finish(
            rng,
            password.as_bytes(),
            server_start_result.registration_response,
            Default::default(),
        )
        .unwrap();

    let response = client::RegisterFinish {
        registration_upload: client_finish_registration_result.message,
    };
    channel.send(response).await?;

    let result: server::RegisterFinish = channel.receive().await?;
    assert!(result.success);

    Ok(client_finish_registration_result.export_key.into())
}
