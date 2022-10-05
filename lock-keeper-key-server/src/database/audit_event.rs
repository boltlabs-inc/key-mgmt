//! Module for operations on audit events in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`AuditEvent`] model in the MongoDB database.

use crate::{constants, LockKeeperServerError};
use futures::TryStreamExt;
use lock_keeper::{
    crypto::KeyId,
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        operations::ClientAction,
        user::AccountName,
    },
};
use mongodb::bson::{doc, Document};

use super::Database;

const ACTION: &str = "action";
const ACTOR: &str = "actor";
const DATE: &str = "date";
const SECRET_ID: &str = "secret_id";

impl Database {
    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    pub async fn create_audit_event(
        &self,
        actor: &AccountName,
        secret_id: &Option<KeyId>,
        action: &ClientAction,
        status: EventStatus,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<AuditEvent>(constants::AUDIT_EVENTS);
        let new_event = AuditEvent::new(actor.clone(), secret_id.clone(), *action, status);
        let _ = collection.insert_one(new_event, None).await?;
        Ok(())
    }

    /// Find [`AuditEvent`]s that correspond to the event type and provided
    /// filters
    pub async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, LockKeeperServerError> {
        let actions = event_type.into_client_actions();
        let mut query = doc! { ACTOR: account_name.to_string(), ACTION: {"$in": mongodb::bson::to_bson(&actions)?} };
        query = construct_query_with_options(options, query)?;
        let collection = self.inner.collection::<AuditEvent>(constants::AUDIT_EVENTS);
        let events = collection.find(query, None).await?;
        let events_vec: Vec<AuditEvent> = events.try_collect().await?;
        Ok(events_vec)
    }
}

fn construct_query_with_options(
    options: AuditEventOptions,
    mut query: Document,
) -> Result<Document, LockKeeperServerError> {
    if let Some(key_ids) = options.key_ids {
        let _ = query.insert(SECRET_ID, doc! {"$in": mongodb::bson::to_bson(&key_ids)?});
    }
    if let Some(after_date) = options.after_date {
        let _ = query.insert(DATE, doc! {"$gte": mongodb::bson::to_bson(&after_date)?});
    }
    if let Some(before_date) = options.before_date {
        let _ = query.insert(DATE, doc! {"$lte": mongodb::bson::to_bson(&before_date)?});
    }

    Ok(query)
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::database::test::{server_registration, setup_db};

    use bson::DateTime;
    use lock_keeper::types::user::UserId;
    use rand::{seq::SliceRandom, CryptoRng, RngCore};
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    const NUM_LOGS: u32 = 10;

    async fn create_user(
        account_name: &str,
        rng: &mut (impl CryptoRng + RngCore),
        db: &Database,
    ) -> Result<(UserId, AccountName), LockKeeperServerError> {
        let user_id = UserId::new(rng)?;
        let account_name = AccountName::from_str(account_name)?;

        let server_registration = server_registration(rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;
        Ok((user_id, account_name))
    }

    async fn create_random_audit_events(
        account_name: &AccountName,
        user_id: &UserId,
        rng: &mut (impl CryptoRng + RngCore),
        db: &Database,
    ) -> Result<Vec<KeyId>, LockKeeperServerError> {
        let action_list = ClientAction::iter().collect::<Vec<_>>();
        let mut key_ids = Vec::new();
        for _ in 0..NUM_LOGS {
            let key_id = KeyId::generate(rng, user_id)?;
            let key_id_copy = key_id.clone();
            let action = action_list.choose(rng).unwrap();
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
        let actual_key_ids: Vec<&KeyId> =
            audit_events.iter().map(|a| a.key_id().unwrap()).collect();
        assert!(actual_key_ids
            .iter()
            .all(|item| expected_key_ids.contains(item)));
    }

    fn check_after_date(audit_events: Vec<AuditEvent>, after_date: DateTime) {
        let actual_dates: Vec<DateTime> = audit_events.iter().map(|a| a.date()).collect();
        assert!(actual_dates.iter().all(|item| after_date < *item));
    }

    #[tokio::test]
    #[ignore]
    async fn event_type_filter_works() -> Result<(), LockKeeperServerError> {
        // Setup db for this test
        let db = setup_db("event_type_filter_works").await?;
        // RNG for this test
        let mut rng = rand::thread_rng();

        // Add a user
        let (user_id, account_name) = create_user("event_type_test", &mut rng, &db).await?;
        // Create random audit events
        let _ = create_random_audit_events(&account_name, &user_id, &mut rng, &db).await?;
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

    #[tokio::test]
    #[ignore]
    async fn key_id_filter_works() -> Result<(), LockKeeperServerError> {
        // Setup db for this test
        let db = setup_db("key_id_filter_works").await?;
        // RNG for this test
        let mut rng = rand::thread_rng();

        // Add a user
        let (user_id, account_name) = create_user("key_id_filter_test", &mut rng, &db).await?;
        // Create random audit events
        let key_ids = create_random_audit_events(&account_name, &user_id, &mut rng, &db).await?;
        // Retrieve audits for just one key
        let options = AuditEventOptions {
            key_ids: Some(key_ids[0..5].to_vec()),
            after_date: None,
            before_date: None,
        };
        let key_audit = db
            .find_audit_events(&account_name, EventType::All, options)
            .await?;

        // Make sure only the first 5 key IDs are included
        compare_key_ids(key_audit, key_ids[0..5].to_vec());

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn after_date_filter_works() -> Result<(), LockKeeperServerError> {
        // Use timestamp as comparison date
        let after_date = DateTime::now();
        // Setup db for this test
        let db = setup_db("after_date_filter_works").await?;
        // RNG for this test
        let mut rng = rand::thread_rng();

        // Add a user
        let (user_id, account_name) = create_user("after_date_filter_test", &mut rng, &db).await?;
        // Create random audit events
        let _ = create_random_audit_events(&account_name, &user_id, &mut rng, &db).await?;
        // Retrieve after the comparison date
        let options = AuditEventOptions {
            key_ids: None,
            after_date: Some(after_date),
            before_date: None,
        };
        let after_date_audit = db
            .find_audit_events(&account_name, EventType::All, options)
            .await?;
        // There should only be one log after "now": the one for RetrieveAuditEvents
        // starting
        check_after_date(after_date_audit, after_date);

        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn before_date_filter_works() -> Result<(), LockKeeperServerError> {
        // Use timestamp as comparison date
        let before_date = DateTime::now();
        // Setup db for this test
        let db = setup_db("before_date_filter_works").await?;
        // RNG for this test
        let mut rng = rand::thread_rng();

        // Add a user
        let (user_id, account_name) = create_user("before_date_filter_test", &mut rng, &db).await?;
        // Create random audit events
        let _ = create_random_audit_events(&account_name, &user_id, &mut rng, &db).await?;
        // Retrieve before the comparison date
        let options = AuditEventOptions {
            key_ids: None,
            after_date: None,
            before_date: Some(before_date),
        };
        let before_date_audit = db
            .find_audit_events(&account_name, EventType::All, options)
            .await?;
        // There shouldn't be any audit events before the comparison date
        assert_eq!(0, before_date_audit.len());

        Ok(())
    }
}
