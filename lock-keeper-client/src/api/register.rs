use crate::{
    client::{LockKeeperClient, Password},
    LockKeeperClientError,
};
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::OpaqueExportKey,
    infrastructure::channel::ClientChannel,
    types::{
        database::user::AccountName,
        operations::register::{client, server},
    },
};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationStartResult,
};
use rand::{CryptoRng, RngCore};

impl LockKeeperClient {
    pub(crate) async fn handle_registration<T: CryptoRng + RngCore>(
        mut channel: ClientChannel,
        rng: &mut T,
        account_name: &AccountName,
        password: &Password,
    ) -> Result<OpaqueExportKey, LockKeeperClientError> {
        // Handle start step
        let client_start_result = register_start(&mut channel, rng, account_name, password).await?;

        // Handle finish step
        let export_key = register_finish(&mut channel, rng, password, client_start_result).await?;

        Ok(export_key)
    }
}

async fn register_start<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    account_name: &AccountName,
    password: &Password,
) -> Result<ClientRegistrationStartResult<OpaqueCipherSuite>, LockKeeperClientError> {
    let client_registration_start_result =
        ClientRegistration::<OpaqueCipherSuite>::start(rng, password.as_bytes())?;

    let response = client::RegisterStart {
        registration_request: client_registration_start_result.message.clone(),
        account_name: account_name.clone(),
    };

    channel.send(response).await?;

    Ok(client_registration_start_result)
}

async fn register_finish<T: CryptoRng + RngCore>(
    channel: &mut ClientChannel,
    rng: &mut T,
    password: &Password,
    client_start_result: ClientRegistrationStartResult<OpaqueCipherSuite>,
) -> Result<OpaqueExportKey, LockKeeperClientError> {
    let server_start_result: server::RegisterStart = channel.receive().await?;

    let client_finish_registration_result = client_start_result.state.finish(
        rng,
        password.as_bytes(),
        server_start_result.registration_response,
        ClientRegistrationFinishParameters::default(),
    )?;

    let response = client::RegisterFinish {
        registration_upload: client_finish_registration_result.message,
    };
    channel.send(response).await?;

    let result: server::RegisterFinish = channel.receive().await?;

    if result.success {
        Ok(client_finish_registration_result.export_key.into())
    } else {
        Err(LockKeeperClientError::ServerReturnedFailure)
    }
}
