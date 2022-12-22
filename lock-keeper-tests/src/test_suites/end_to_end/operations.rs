use crate::{test_suites::end_to_end::test_cases::TestState, LockKeeperTestError};
use lock_keeper::{
    crypto::{Import, KeyId},
    types::{
        audit_event::{AuditEventOptions, EventStatus, EventType},
        operations::ClientAction,
    },
};
use lock_keeper_client::{LockKeeperClient, LockKeeperClientError, LockKeeperResponse};
use rand::{prelude::StdRng, Rng, SeedableRng};
use std::fmt::Display;
use tonic::Status;
use uuid::Uuid;

/// Generate a fake key ID to test retrieve/export failure cases.
pub(crate) async fn generate_fake_key_id(
    client: &LockKeeperClient,
) -> Result<KeyId, LockKeeperClientError> {
    let mut rng = StdRng::from_entropy();
    let fake_key_id = KeyId::generate(&mut rng, client.user_id())?;

    Ok(fake_key_id)
}

/// Helper to compare result errors.
pub(crate) fn compare_errors<T, E>(result: LockKeeperResponse<T>, expected_error: E)
where
    E: Into<LockKeeperClientError> + Display,
{
    assert!(result.result.is_err());

    let actual_error = result.result.err().unwrap();
    assert_eq!(actual_error.to_string(), expected_error.to_string());
}

/// Helper to compare status errors.
pub(crate) fn compare_status_errors<T>(
    res: LockKeeperResponse<T>,
    expected: Status,
) -> Result<(), LockKeeperTestError> {
    let actual = match res.result.err().unwrap() {
        LockKeeperClientError::TonicStatus(status) => Ok(status),
        _ => Err(LockKeeperTestError::WrongErrorReturned),
    }?;

    assert_eq!(actual.code(), expected.code());
    assert_eq!(actual.message(), expected.message());

    Ok(())
}

/// Make sure the last audit log for the tested operation has the correct status
/// and action.
pub(crate) async fn check_audit_events(
    state: &TestState,
    expected_status: EventStatus,
    expected_action: ClientAction,
    request_id: Uuid,
) -> Result<(), LockKeeperClientError> {
    // Authenticate to LockKeeperClient
    let lock_keeper_client =
        LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
            .await
            .result?;
    // Get audit event log for the specific request
    let options = AuditEventOptions {
        request_id: Some(request_id),
        ..Default::default()
    };
    let audit_event_log = lock_keeper_client
        .retrieve_audit_event_log(EventType::All, options)
        .await
        .result?;

    // Get the last event in the list of events
    let last_event = audit_event_log.last().unwrap();

    // Check that expected status and action match
    let actual_status = last_event.status();
    let actual_action = last_event.action();
    assert_eq!(expected_status, actual_status);
    assert_eq!(expected_action, actual_action);
    Ok(())
}

/// Authenticate to the LockKeeper key server and get a LockKeeperClient.
pub(crate) async fn authenticate(state: &TestState) -> LockKeeperResponse<LockKeeperClient> {
    LockKeeperClient::authenticated_client(&state.account_name, &state.password, &state.config)
        .await
}

/// Authenticate and import a signing key.
pub(crate) async fn import_signing_key(
    client: &LockKeeperClient,
) -> LockKeeperResponse<(KeyId, Vec<u8>)> {
    // Authenticate and run generate
    let random_bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let import = Import::new(random_bytes.clone()).unwrap();
    let LockKeeperResponse { result, metadata } = client.import_signing_key(import).await;

    let result = match result {
        Ok(key_id) => Ok((key_id, random_bytes)),
        Err(e) => Err(e),
    };

    LockKeeperResponse { result, metadata }
}
