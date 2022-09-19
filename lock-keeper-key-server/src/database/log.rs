//! Module for operations on log entries in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`LogEntry`] model in the MongoDB database.

use crate::{constants, LockKeeperServerError};
use async_trait::async_trait;
use lock_keeper::{
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
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<LogEntry>(constants::LOGS);
        let new_log = LogEntry::new(actor.into(), secret_id, action, outcome);
        let _ = collection.insert_one(new_log, None).await?;
        Ok(())
    }
}

#[async_trait]
pub trait AuditLogExt {
    async fn audit_log(
        self,
        db: &Database,
        actor: impl Into<LogIdentifier> + std::marker::Send + 'async_trait,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Self;
}

#[async_trait]
impl<T: std::marker::Send> AuditLogExt for Result<T, LockKeeperServerError> {
    async fn audit_log(
        self,
        db: &Database,
        actor: impl Into<LogIdentifier> + std::marker::Send + 'async_trait,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Self {
        if self.is_err() {
            db.create_log_entry(actor, secret_id, action, Outcome::Failed)
                .await?;
        } else {
            db.create_log_entry(actor, secret_id, action, Outcome::Successful)
                .await?;
        }
        self
    }
}
