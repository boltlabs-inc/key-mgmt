//! Audit events, and associated fields and types
//!
//! Includes possible events to log and statuses of those events

use crate::user::AccountName;

use crate::{crypto::KeyId, ClientAction};
use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Options for the outcome of a given action in a [`AuditEvent`]
#[derive(Debug, Serialize, Deserialize)]
pub enum EventStatus {
    Started,
    Successful,
    Failed,
}

/// A single entry that specifies the actor, action, outcome, and
/// any related key for a logged audit event
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    actor: AccountName,
    secret_id: Option<KeyId>,
    date: DateTime,
    action: ClientAction,
    status: EventStatus,
}

impl AuditEvent {
    pub fn new(
        actor: AccountName,
        secret_id: Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Self {
        AuditEvent {
            actor,
            secret_id,
            date: DateTime::now(),
            action,
            status,
        }
    }
}

impl Display for AuditEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AuditEvent: User <{:?}> performed action <{:?}> on {} with outcome <{:?}>",
            self.actor, self.action, self.date, self.status
        )
    }
}
