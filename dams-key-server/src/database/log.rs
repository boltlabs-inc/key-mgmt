//! Module for operations on log entries in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`LogEntry`] model in the MongoDB database.

use crate::{constants, DamsServerError};
use dams::{
    audit_log::{LogEntry, Outcome},
    crypto::KeyId,
    user::LogIdentifier,
    ClientAction,
};
use mongodb::Database;

/// Create a new [`LogEntry`] for the given actor, action, and outcome
pub async fn create_log_entry(
    db: &Database,
    actor: &LogIdentifier,
    secret_id: Option<KeyId>,
    action: ClientAction,
    outcome: Outcome,
) -> Result<(), DamsServerError> {
    let collection = db.collection::<LogEntry>(constants::LOGS);
    let new_log = LogEntry::new(actor.clone(), secret_id, action, outcome);
    let _ = collection.insert_one(new_log, None).await?;
    Ok(())
}
