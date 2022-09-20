//! Module for operations on log entries in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`LogEntry`] model in the MongoDB database.

use crate::{constants, server::Context, LockKeeperServerError};
use async_trait::async_trait;
use lock_keeper::{
    audit_log::{LogEntry, Outcome},
    channel::ServerChannel,
    crypto::KeyId,
    user::AccountName,
    ClientAction,
};
use std::{thread, time::Duration};
use tonic::Status;

use super::Database;

impl Database {
    /// Create a new [`LogEntry`] for the given actor, action, and outcome
    pub async fn create_log_entry(
        &self,
        actor: &AccountName,
        secret_id: Option<KeyId>,
        action: ClientAction,
        outcome: Outcome,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<LogEntry>(constants::LOGS);
        let new_log = LogEntry::new(actor.clone(), secret_id, action, outcome);
        let _ = collection.insert_one(new_log, None).await?;
        Ok(())
    }
}

#[async_trait]
pub trait AuditLogExt {
    async fn audit_log(
        self,
        channel: &mut ServerChannel,
        context: &Context,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Result<(), LockKeeperServerError>;
}

#[async_trait]
impl<T: std::marker::Send> AuditLogExt for Result<T, LockKeeperServerError> {
    async fn audit_log(
        self,
        channel: &mut ServerChannel,
        context: &Context,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Result<(), LockKeeperServerError> {
        if self.is_err() {
            // Send error to client
            let e = self
                .err()
                .ok_or_else(|| Status::internal("Unable to unwrap error"))?;
            tracing::error!("{}", e);
            if let Err(e) = channel.send_error(e).await {
                tracing::error!("{}", e);
            }
            // Log action
            context
                .db
                .create_log_entry(&context.account_name, secret_id, action, Outcome::Failed)
                .await?;
            // Give the client a moment to receive the error before dropping the channel
            thread::sleep(Duration::from_millis(100));
            Ok(())
        } else {
            Ok(context
                .db
                .create_log_entry(
                    &context.account_name,
                    secret_id,
                    action,
                    Outcome::Successful,
                )
                .await?)
        }
    }
}
