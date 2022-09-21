//! Module for operations on audit events in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`AuditEvent`] model in the MongoDB database.

use crate::{
    constants,
    server::{Context, OperationResult},
    LockKeeperServerError,
};
use async_trait::async_trait;
use lock_keeper::{
    audit_event::{AuditEvent, Outcome},
    channel::ServerChannel,
    crypto::KeyId,
    user::AccountName,
    ClientAction,
};
use std::{thread, time::Duration};

use super::Database;

impl Database {
    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    pub async fn create_audit_event(
        &self,
        actor: &AccountName,
        secret_id: Option<KeyId>,
        action: ClientAction,
        outcome: Outcome,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<AuditEvent>(constants::AUDIT_EVENTS);
        let new_event = AuditEvent::new(actor.clone(), secret_id, action, outcome);
        let _ = collection.insert_one(new_event, None).await?;
        Ok(())
    }
}

#[async_trait]
pub trait AuditEventExt {
    async fn log_audit_event(
        self,
        channel: &mut ServerChannel,
        context: &Context,
        action: ClientAction,
    ) -> Result<(), LockKeeperServerError>;
}

#[async_trait]
impl AuditEventExt for Result<OperationResult, LockKeeperServerError> {
    async fn log_audit_event(
        self,
        channel: &mut ServerChannel,
        context: &Context,
        action: ClientAction,
    ) -> Result<(), LockKeeperServerError> {
        match self {
            Ok(op_result) => Ok(context
                .db
                .create_audit_event(
                    &context.account_name,
                    op_result.0,
                    action,
                    Outcome::Successful,
                )
                .await?),
            Err(e) => {
                tracing::error!("{}", e);
                if let Err(e) = channel.send_error(e).await {
                    tracing::error!("{}", e);
                }
                // Log action
                context
                    .db
                    .create_audit_event(&context.account_name, None, action, Outcome::Failed)
                    .await?;
                // Give the client a moment to receive the error before dropping the channel
                thread::sleep(Duration::from_millis(100));
                Ok(())
            }
        }
    }
}
