use crate::end_to_end::test_cases::TestState;
use lock_keeper::{
    config::client::Config,
    crypto::{Export, KeyId, Secret, Signable, Signature},
    types::{
        audit_event::{AuditEventOptions, EventStatus, EventType},
        database::user::AccountName,
        operations::{retrieve::RetrieveContext, ClientAction},
    },
};
use lock_keeper_client::{
    api::{LocalStorage, RemoteGenerateResult},
    client::Password,
    LockKeeperClient, LockKeeperClientError,
};
use rand::{prelude::StdRng, Rng, SeedableRng};

/// Generate a fake key ID to test retrieve/export failure cases.
pub(crate) async fn generate_fake_key_id(
    state: &TestState,
) -> Result<KeyId, LockKeeperClientError> {
    let client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;
    let mut rng = StdRng::from_entropy();
    let fake_key_id = KeyId::generate(&mut rng, client.user_id())?;

    Ok(fake_key_id)
}

/// Helper to compare result errors.
pub(crate) fn compare_errors<T>(
    result: Result<T, LockKeeperClientError>,
    expected_error: LockKeeperClientError,
) {
    assert!(result.is_err());

    let actual_error = result.err().unwrap();
    assert_eq!(actual_error.to_string(), expected_error.to_string())
}

/// Make sure the last audit log for the tested operation has the correct status
/// and action.
pub(crate) async fn check_audit_events(
    state: &TestState,
    expected_status: EventStatus,
    expected_action: ClientAction,
) -> Result<(), LockKeeperClientError> {
    // Authenticate to LockKeeperClient
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;

    // Get audit event log
    let audit_event_log = lock_keeper_client
        .retrieve_audit_event_log(EventType::All, AuditEventOptions::default())
        .await?;

    // Get the fourth last event, the last 3 are for retrieving audit logs and
    // authenticating
    let fourth_last = audit_event_log
        .len()
        .checked_sub(4)
        .map(|i| &audit_event_log[i]);
    assert!(fourth_last.is_some());

    let fourth_last = fourth_last.unwrap();
    // Check that expected status and action match
    let actual_status = fourth_last.status();
    let actual_action = fourth_last.action();
    assert_eq!(expected_status, actual_status);
    assert_eq!(expected_action, actual_action);
    Ok(())
}

/// Authenticate to the LockKeeper key server and get a LockKeeperClient.
pub(crate) async fn authenticate(
    state: &TestState,
) -> Result<LockKeeperClient, LockKeeperClientError> {
    LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
        .await
}

/// Authenticate and export an arbitrary secret by KeyId.
pub(crate) async fn export(
    state: &TestState,
    key_id: &KeyId,
) -> Result<Vec<u8>, LockKeeperClientError> {
    // Authenticate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;

    lock_keeper_client.export_key(key_id).await
}

/// Authenticate and export a signing key by KeyId.
pub(crate) async fn export_signing_key(
    state: &TestState,
    key_id: &KeyId,
) -> Result<Export, LockKeeperClientError> {
    // Authenticate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;

    lock_keeper_client.export_signing_key(key_id).await
}

/// Authenticate and generate an arbitrary key.
pub(crate) async fn generate(
    state: &TestState,
) -> Result<(KeyId, LocalStorage<Secret>), LockKeeperClientError> {
    // Authenticate and run generate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;
    let (key_id, local_storage) = lock_keeper_client.generate_and_store().await?;

    Ok((key_id, local_storage))
}

/// Authenticate and import a signing key.
pub(crate) async fn import_signing_key(
    state: &TestState,
) -> Result<(KeyId, Vec<u8>), LockKeeperClientError> {
    // Authenticate and run generate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let key_id = lock_keeper_client
        .import_signing_key(random_bytes.clone())
        .await?;

    Ok((key_id, random_bytes))
}

/// Register to the LockKeeper key server.
pub(crate) async fn register(
    account_name: &AccountName,
    password: &Password,
    config: &Config,
) -> Result<(), LockKeeperClientError> {
    LockKeeperClient::register(account_name, password, config).await?;

    Ok(())
}

/// Authenticate and generate a signing key server-side
pub(crate) async fn remote_generate(
    state: &TestState,
) -> Result<RemoteGenerateResult, LockKeeperClientError> {
    // Authenticate and run remote generate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;
    lock_keeper_client.remote_generate().await
}

/// Authenticate and sign bytes with a remote generated signing key
pub(crate) async fn remote_sign_bytes(
    state: &TestState,
    key_id: &KeyId,
    bytes: impl Signable,
) -> Result<Signature, LockKeeperClientError> {
    // Authenticate and run remote generate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;
    lock_keeper_client
        .remote_sign_bytes(key_id.clone(), bytes)
        .await
}

/// Authenticate and retrieve an arbitrary key by KeyId.
pub(crate) async fn retrieve(
    state: &TestState,
    key_id: &KeyId,
    context: RetrieveContext,
) -> Result<Option<LocalStorage<Secret>>, LockKeeperClientError> {
    // Authenticate
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await?;

    // Ensure result matches what was stored in generate
    lock_keeper_client.retrieve(key_id, context).await
}
