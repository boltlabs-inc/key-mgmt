//! Module for operations on audit events in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`AuditEvent`] model in the MongoDB database.

use crate::{
    constants::{AUDIT_EVENTS, MAX_AUDIT_ENTRIES},
    LockKeeperServerError,
};
use futures::TryStreamExt;
use lock_keeper::{
    crypto::KeyId,
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::user::AccountName,
        operations::ClientAction,
    },
};
use mongodb::{
    bson::{doc, Document},
    options::FindOptions,
};

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
        let collection = self.inner.collection::<AuditEvent>(AUDIT_EVENTS);
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
        let collection = self.inner.collection::<AuditEvent>(AUDIT_EVENTS);
        let find_options = FindOptions::builder().limit(MAX_AUDIT_ENTRIES).build();
        let events = collection.find(query, Some(find_options)).await?;
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
