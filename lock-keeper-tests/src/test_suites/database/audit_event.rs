//! Integration tests for audit event objects in the database

use colored::Colorize;
use lock_keeper::{
    crypto::KeyId,
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::user::{AccountName, UserId},
        operations::ClientAction,
    },
};
use lock_keeper_key_server::database::DataStore;

use rand::{
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
    SeedableRng,
};
use strum::IntoEnumIterator;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{config::TestFilters, error::Result, run_parallel, utils::TestResult};

use super::TestDatabase;

pub async fn run_tests(filters: &TestFilters) -> Result<Vec<TestResult>> {
    println!("{}", "Running audit event tests".cyan());

    let db = TestDatabase::connect().await?;
    let result = run_parallel!(
        filters,
        event_type_filter_works(db.clone()),
        key_id_filter_works(db.clone()),
        after_date_filter_works(db.clone()),
        before_date_filter_works(db.clone()),
        request_id_filter_works(db.clone()),
        store_audit_event_identity(db.clone()),
    )?;

    Ok(result)
}

const NUM_LOGS: u32 = 10;
const NUM_SAMPLE: usize = NUM_LOGS as usize / 2;

/// Tests that storing an event returns the same event back out.
async fn store_audit_event_identity(db: TestDatabase) -> Result<()> {
    // Create and store a single audit event.
    let mut rng = StdRng::from_entropy();
    let action_list = ClientAction::iter().collect::<Vec<_>>();
    let (user_id, account_name) = db.create_test_user().await?;

    let (key_id, request_id, action) =
        create_random_audit_event(&mut rng, &action_list, &user_id, account_name.clone(), &db)
            .await?;

    let options = AuditEventOptions {
        request_id: Some(request_id),
        ..Default::default()
    };
    let mut events = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    assert_eq!(events.len(), 1, "Multiple events found.");
    let stored_event = events.pop().unwrap();
    assert_eq!(action, stored_event.action);
    assert_eq!(account_name, stored_event.account_name);
    // Our create_random_event function always uses EventStatus::Started.
    assert_eq!(EventStatus::Started, stored_event.status);
    assert_eq!(key_id, stored_event.key_id.unwrap());

    // Do not compare timestamp. Some precision is lost when storing and retrieving.
    // assert_eq!(audit_event.timestamp, stored_event.timestamp);
    Ok(())
}

/// Check that the DB test filters work by ensuring queries to the DB with
/// specific [`EventType`]s return only the specified types of audit event log
/// events.
async fn event_type_filter_works(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    // Create random audit events
    let _ = create_random_audit_events(&account_name, &user_id, &db).await?;

    // Retrieve all 3 types of audit events
    let key_only_audit = db
        .find_audit_events(
            &account_name,
            EventType::KeyOnly,
            AuditEventOptions::default(),
        )
        .await?;

    let system_only_audit = db
        .find_audit_events(
            &account_name,
            EventType::SystemOnly,
            AuditEventOptions::default(),
        )
        .await?;

    let all_audit = db
        .find_audit_events(&account_name, EventType::All, AuditEventOptions::default())
        .await?;

    // Make sure our audit events have the correct actions.
    compare_actions(key_only_audit, EventType::KeyOnly);
    compare_actions(system_only_audit, EventType::SystemOnly);
    compare_actions(all_audit, EventType::All);

    Ok(())
}

async fn key_id_filter_works(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    let (key_ids, _) = create_random_audit_events(&account_name, &user_id, &db).await?;

    let sample = {
        let mut rng = rand::thread_rng();
        key_ids.into_iter().choose_multiple(&mut rng, NUM_SAMPLE)
    };

    let options = AuditEventOptions {
        key_ids: sample.clone(),
        ..Default::default()
    };
    let key_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Make sure only the sampled key IDs are included
    compare_key_ids(key_audit, sample);

    Ok(())
}

async fn after_date_filter_works(db: TestDatabase) -> Result<()> {
    // Add a user
    let (user_id, account_name) = db.create_test_user().await?;

    // Use timestamp as comparison date
    let after_date = OffsetDateTime::now_utc();

    // Create random audit events
    let _ = create_random_audit_events(&account_name, &user_id, &db).await?;

    // Retrieve after the comparison date
    let options = AuditEventOptions {
        after_date: Some(after_date),
        ..Default::default()
    };
    let after_date_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Check that there are only audit events that happened after "after_date"
    check_after_date(after_date_audit, after_date);

    Ok(())
}

async fn before_date_filter_works(db: TestDatabase) -> Result<()> {
    // Add a user
    let (user_id, account_name) = db.create_test_user().await?;

    // Use timestamp as comparison date
    let before_date = OffsetDateTime::now_utc();

    // Create random audit events
    let _ = create_random_audit_events(&account_name, &user_id, &db).await?;

    // Retrieve before the comparison date
    let options = AuditEventOptions {
        before_date: Some(before_date),
        ..Default::default()
    };
    let before_date_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Check that there are only audit events that happened before "before_date"
    check_before_date(before_date_audit, before_date);

    Ok(())
}

async fn request_id_filter_works(db: TestDatabase) -> Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    let (_, uudis) = create_random_audit_events(&account_name, &user_id, &db).await?;

    let sample: Uuid = {
        let mut rng = rand::thread_rng();
        uudis.into_iter().choose(&mut rng).unwrap()
    };

    // Retrieve audits for just one key
    let options = AuditEventOptions {
        request_id: Some(sample),
        ..Default::default()
    };
    let request_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Make sure only the sampled request ID is included
    compare_request_ids(request_audit, sample);

    Ok(())
}

/// Create [NUM_LOGS] random audit events and store them in our database. Return
/// the [KeyId]s and [Uuid]s (request IDs) assigned to these audit events.
async fn create_random_audit_events(
    account_name: &AccountName,
    user_id: &UserId,
    db: &TestDatabase,
) -> Result<(Vec<KeyId>, Vec<Uuid>)> {
    let mut rng = StdRng::from_entropy();

    let action_list = ClientAction::iter().collect::<Vec<_>>();
    let mut keys = Vec::new();
    let mut uuids = Vec::new();

    for _ in 0..NUM_LOGS {
        let (key_id, request_id, _) =
            create_random_audit_event(&mut rng, &action_list, user_id, account_name.clone(), db)
                .await?;

        // Key IDs should always exist for these randomly generated audit events.
        keys.push(key_id);
        uuids.push(request_id);
    }
    Ok((keys, uuids))
}

/// Create a single random audit event and store it in our DB.
async fn create_random_audit_event(
    rng: &mut StdRng,
    action_list: &Vec<ClientAction>,
    user_id: &UserId,
    account_name: AccountName,
    db: &TestDatabase,
) -> Result<(KeyId, Uuid, ClientAction)> {
    let key_id = KeyId::generate(rng, user_id)?;
    let action = action_list.choose(rng).unwrap();
    let request_id = Uuid::new_v4();

    db.create_audit_event(
        request_id,
        &account_name,
        &Some(key_id.clone()),
        *action,
        EventStatus::Started,
    )
    .await?;

    Ok((key_id, request_id, *action))
}

fn compare_actions(audit_events: Vec<AuditEvent>, event_type: EventType) {
    // Ensure we have some events, otherwise the assert below will be vacuously true
    // (since the loop not execute).
    assert!(
        !audit_events.is_empty(),
        "No AuditEvents actions to compare."
    );

    let actual_actions: Vec<ClientAction> = audit_events.iter().map(|a| a.action()).collect();
    let expected_actions = event_type.client_actions();

    for a in actual_actions {
        assert!(
            expected_actions.contains(&a),
            "{:?} not in {:?}",
            a,
            event_type,
        )
    }
}

fn compare_key_ids(audit_events: Vec<AuditEvent>, expected_key_ids: Vec<KeyId>) {
    let actual_key_ids: Vec<&KeyId> = audit_events.iter().map(|a| a.key_id().unwrap()).collect();
    assert!(actual_key_ids
        .iter()
        .all(|item| expected_key_ids.contains(item)));
}

/// We expect all events to have the request_id we specified. Check this.
fn compare_request_ids(audit_events: Vec<AuditEvent>, expected_request_id: Uuid) {
    let actual_request_ids = audit_events.iter().map(|a| a.request_id());
    for item in actual_request_ids {
        assert_eq!(*item, expected_request_id, "Incorrect request ID found!")
    }
}

fn check_after_date(audit_events: Vec<AuditEvent>, after_date: OffsetDateTime) {
    let actual_dates: Vec<OffsetDateTime> = audit_events.iter().map(|a| a.date()).collect();
    assert!(actual_dates.iter().all(|date| after_date <= *date));
}

fn check_before_date(audit_events: Vec<AuditEvent>, before_date: OffsetDateTime) {
    let actual_dates: Vec<OffsetDateTime> = audit_events.iter().map(|a| a.date()).collect();
    assert!(actual_dates.iter().all(|date| before_date >= *date));
}
