//! Module for operations on audit events in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`AuditEvent`] model in the MongoDB database.

use crate::{constants, LockKeeperServerError};
use lock_keeper::{
    audit_event::{AuditEvent, Outcome},
    crypto::KeyId,
    user::AccountName,
    ClientAction,
};

use super::Database;

impl Database {
    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    pub async fn create_audit_event(
        &self,
        actor: &AccountName,
        secret_id: &Option<KeyId>,
        action: &ClientAction,
        outcome: Outcome,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<AuditEvent>(constants::AUDIT_EVENTS);
        let new_event = AuditEvent::new(actor.clone(), secret_id.clone(), action.clone(), outcome);
        let _ = collection.insert_one(new_event, None).await?;
        Ok(())
    }
}
