use std::str::FromStr;

use common::TestContext;
use dams::{ClientAction, user::AccountName, config::opaque::OpaqueCipherSuite, types::register::{client, server}};
use dams_client::client::Password;
use dams_key_server::database::user::{find_user};
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters};
use rand::{rngs::StdRng, SeedableRng};

mod common;

#[tokio::test]
async fn test_user_deleted_if_create_storage_key_fails() -> anyhow::Result<()> {
    let context = common::setup().await;
    
    let account_name = AccountName::from_str("test_user_deleted_user")?;
    let password = Password::from_str("testPassword")?;

    register(&context, &account_name, &password).await?;

    let user = find_user(&context.database, &account_name).await?;

    context.teardown().await;
    
    Ok(())
}

/// Performs the same registration code as [`DamsClient`] without triggering authentication or storage key creation
async fn register(context: &TestContext, account_name: &AccountName, password: &Password) -> anyhow::Result<()> {
    let mut rng = StdRng::from_entropy();
    let mut channel = context.create_channel(ClientAction::Register).await?;

    let client_registration_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();

    let response = client::RegisterStart {
        registration_request: client_registration_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(response).await?;

    let server_start_result: server::RegisterStart = channel.receive().await?;

    let client_finish_registration_result = client_registration_start_result.state.finish(
        &mut rng,
        password.as_bytes(),
        server_start_result.registration_response,
        ClientRegistrationFinishParameters::default(),
    ).unwrap();

    let response = client::RegisterFinish {
        registration_upload: client_finish_registration_result.message,
    };
    channel.send(response).await?;

    let _: server::RegisterFinish = channel.receive().await?;

    Ok(())
}
