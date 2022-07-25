//! Module for operations on log entries in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`LogEntry`] model in the MongoDB database.

use dams::{
    audit_log::{Action, LogEntry, Outcome},
    user::UserId,
};
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    Database,
};

/// Create a new [`LogEntry`] for the given actor, action, and outcome
pub async fn create_log_entry(
    db: &Database,
    actor: &UserId,
    secret_id: Option<ObjectId>,
    action: Action,
    outcome: Outcome,
) -> Result<Option<ObjectId>, Error> {
    let collection = db.collection::<LogEntry>("log_entries");
    let new_log = LogEntry::new(actor.clone(), secret_id, action, outcome);
    let insert_one_res = collection.insert_one(new_log, None).await?;
    Ok(insert_one_res.inserted_id.as_object_id())
}
