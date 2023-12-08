use crate::{test_suites::end_to_end::test_cases::TestState, LockKeeperTestError};
use lock_keeper_client::lock_keeper::{
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
    assert!(
        result.result.is_err(),
        "Expected error. Found value instead."
    );

    let actual_error = result.result.err().unwrap();
    assert_eq!(
        actual_error.to_string(),
        expected_error.to_string(),
        "Wrong error found."
    );
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

/// Fetch relevant events based on request_id. Ensure that some event on the
/// list matches the expected_status and expected_action. Note: we cannot rely
/// on the ordering of the audit events.
pub(crate) async fn check_audit_events(
    state: &TestState,
    expected_status: EventStatus,
    expected_action: ClientAction,
    request_id: Uuid,
    key_id: Option<KeyId>,
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

    // Get all events that match given expected values.
    let matching_events = audit_event_log.iter().filter(|event| {
        event.key_id == key_id
            && event.status == expected_status
            && event.client_action == expected_action
    });

    assert_eq!(
        matching_events.count(),
        1,
        "Exactly one audit event should have matched. All events: {audit_event_log:?}",
    );

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
