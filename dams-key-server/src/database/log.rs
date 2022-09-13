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

use super::Database;

impl Database {
    /// Create a new [`LogEntry`] for the given actor, action, and outcome
    pub async fn create_log_entry(
        &self,
        actor: impl Into<LogIdentifier> + std::marker::Send,
        secret_id: Option<KeyId>,
        action: ClientAction,
        outcome: Outcome,
    ) -> Result<(), DamsServerError> {
        let collection = self.inner.collection::<LogEntry>(constants::LOGS);
        let new_log = LogEntry::new(actor.into(), secret_id, action, outcome);
        let _ = collection.insert_one(new_log, None).await?;
        Ok(())
    }
}
