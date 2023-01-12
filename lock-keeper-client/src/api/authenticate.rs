use crate::client::{AuthenticateResult, LockKeeperClient, Password};
use std::sync::Arc;

use crate::LockKeeperClientError;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::{MasterKey, OpaqueSessionKey},
    infrastructure::channel::{ClientChannel, Unauthenticated},
    types::{
        database::user::AccountName,
        operations::authenticate::{client, server},
    },
};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult};
use rand::rngs::StdRng;
use tokio::sync::Mutex;

impl LockKeeperClient {
    pub(crate) async fn handle_authentication(
        mut channel: ClientChannel<Unauthenticated>,
        rng: Arc<Mutex<StdRng>>,
        account_name: &AccountName,
        password: &Password,
    ) -> Result<AuthenticateResult, LockKeeperClientError> {
        let client_login_start_result = {
            let mut rng = rng.lock().await;
            ClientLogin::<OpaqueCipherSuite>::start(&mut *rng, password.as_bytes())?
        };

        // Handle start step
        let server_start_result =
            authenticate_start(&mut channel, &client_login_start_result, account_name).await?;

        // Handle finish step
        let auth_result = authenticate_finish(
            &mut channel,
            account_name,
            password,
            client_login_start_result,
            server_start_result,
        )
        .await?;

        Ok(auth_result)
    }
}

async fn authenticate_start(
    channel: &mut ClientChannel<Unauthenticated>,
    client_login_start_result: &ClientLoginStartResult<OpaqueCipherSuite>,
    account_name: &AccountName,
) -> Result<server::AuthenticateStart, LockKeeperClientError> {
    let reply = client::AuthenticateStart {
        credential_request: client_login_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(reply).await?;

    Ok(channel.receive().await?)
}

async fn authenticate_finish(
    channel: &mut ClientChannel<Unauthenticated>,
    account_name: &AccountName,
    password: &Password,
    client_start_result: ClientLoginStartResult<OpaqueCipherSuite>,
    server_start_result: server::AuthenticateStart,
) -> Result<AuthenticateResult, LockKeeperClientError> {
    let client_login_finish_result = client_start_result.state.finish(
        password.as_bytes(),
        server_start_result.credential_response,
        ClientLoginFinishParameters::default(),
    )?;

    let reply = client::AuthenticateFinish {
        credential_finalization: client_login_finish_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(reply).await?;

    let server_finish: server::AuthenticateFinish = channel.receive().await?;

    let session_key: OpaqueSessionKey = client_login_finish_result.session_key.try_into()?;
    let master_key = MasterKey::derive_master_key(client_login_finish_result.export_key)?;

    Ok(AuthenticateResult {
        session_id: server_finish.session_id,
        session_key,
        master_key,
    })
}
