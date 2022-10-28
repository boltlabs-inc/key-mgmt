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
use lock_keeper_key_server::{database::Database, LockKeeperServerError};
use mongodb::bson::DateTime;
use rand::{
    rngs::StdRng,
    seq::{IteratorRandom, SliceRandom},
    SeedableRng,
};
use strum::IntoEnumIterator;

use crate::{run_parallel, utils::TestResult, Config};

use super::TestDatabase;

pub async fn run_tests(config: Config) -> anyhow::Result<Vec<TestResult>> {
    println!("{}", "Running audit event tests".cyan());

    let db = TestDatabase::new("audit_event_tests").await?;
    let result = run_parallel!(
        config.clone(),
        event_type_filter_works(db.clone()),
        key_id_filter_works(db.clone()),
        after_date_filter_works(db.clone()),
        before_date_filter_works(db.clone())
    )?;

    db.drop().await?;

    Ok(result)
}

const NUM_LOGS: u32 = 10;
const NUM_SAMPLE: usize = NUM_LOGS as usize / 2;

async fn create_random_audit_events(
    account_name: &AccountName,
    user_id: &UserId,
    db: &Database,
) -> Result<Vec<KeyId>, LockKeeperServerError> {
    let mut rng = StdRng::from_entropy();

    let action_list = ClientAction::iter().collect::<Vec<_>>();
    let mut key_ids = Vec::new();
    for _ in 0..NUM_LOGS {
        let key_id = KeyId::generate(&mut rng, user_id)?;
        let key_id_copy = key_id.clone();
        let action = action_list.choose(&mut rng).unwrap();
        db.create_audit_event(account_name, &Some(key_id), action, EventStatus::Started)
            .await?;
        key_ids.push(key_id_copy);
    }
    Ok(key_ids)
}

fn compare_actions(audit_events: Vec<AuditEvent>, event_type: EventType) {
    let actual_actions: Vec<ClientAction> = audit_events.iter().map(|a| a.action()).collect();
    let expected_actions = event_type.into_client_actions();
    assert!(actual_actions
        .iter()
        .all(|item| expected_actions.contains(item)));
}

fn compare_key_ids(audit_events: Vec<AuditEvent>, expected_key_ids: Vec<KeyId>) {
    let actual_key_ids: Vec<&KeyId> = audit_events.iter().map(|a| a.key_id().unwrap()).collect();
    assert!(actual_key_ids
        .iter()
        .all(|item| expected_key_ids.contains(item)));
}

fn check_after_date(audit_events: Vec<AuditEvent>, after_date: DateTime) {
    let actual_dates: Vec<DateTime> = audit_events.iter().map(|a| a.date()).collect();
    assert!(actual_dates.iter().all(|item| after_date <= *item));
}

fn check_before_date(audit_events: Vec<AuditEvent>, before_date: DateTime) {
    let actual_dates: Vec<DateTime> = audit_events.iter().map(|a| a.date()).collect();
    assert!(actual_dates.iter().all(|item| before_date >= *item));
}

async fn event_type_filter_works(db: TestDatabase) -> anyhow::Result<()> {
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

    // Make sure each type has the correct actions
    compare_actions(key_only_audit, EventType::KeyOnly);
    compare_actions(system_only_audit, EventType::SystemOnly);
    compare_actions(all_audit, EventType::All);

    Ok(())
}

async fn key_id_filter_works(db: TestDatabase) -> anyhow::Result<()> {
    let (user_id, account_name) = db.create_test_user().await?;

    let key_ids = create_random_audit_events(&account_name, &user_id, &db).await?;

    let sample = {
        let mut rng = rand::thread_rng();
        key_ids.into_iter().choose_multiple(&mut rng, NUM_SAMPLE)
    };

    // Retrieve audits for just one key
    let options = AuditEventOptions {
        key_ids: Some(sample.clone()),
        after_date: None,
        before_date: None,
    };
    let key_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Make sure only the first 5 key IDs are included
    compare_key_ids(key_audit, sample);

    Ok(())
}

async fn after_date_filter_works(db: TestDatabase) -> anyhow::Result<()> {
    // Add a user
    let (user_id, account_name) = db.create_test_user().await?;

    // Use timestamp as comparison date
    let after_date = DateTime::now();

    // Create random audit events
    let _ = create_random_audit_events(&account_name, &user_id, &db).await?;

    // Retrieve after the comparison date
    let options = AuditEventOptions {
        key_ids: None,
        after_date: Some(after_date),
        before_date: None,
    };
    let after_date_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Check that there are only audit events that happened after "after_date"
    check_after_date(after_date_audit, after_date);

    Ok(())
}

async fn before_date_filter_works(db: TestDatabase) -> anyhow::Result<()> {
    // Add a user
    let (user_id, account_name) = db.create_test_user().await?;

    // Use timestamp as comparison date
    let before_date = DateTime::now();

    // Create random audit events
    let _ = create_random_audit_events(&account_name, &user_id, &db).await?;

    // Retrieve before the comparison date
    let options = AuditEventOptions {
        key_ids: None,
        after_date: None,
        before_date: Some(before_date),
    };
    let before_date_audit = db
        .find_audit_events(&account_name, EventType::All, options)
        .await?;

    // Check that there are only audit events that happened before "before_date"
    check_before_date(before_date_audit, before_date);

    Ok(())
}
