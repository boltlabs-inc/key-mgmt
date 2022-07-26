//! Audit log entries, fields, and types
//!
//! Includes possible actions to log and outcomes of those actions

use crate::user::AccountName;

use crate::crypto::KeyId;
use mongodb::bson::DateTime;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Options for which action was taken for a given [`LogEntry`]
#[derive(Debug, Serialize, Deserialize)]
pub enum Action {
    Register,
    Authenticate,
}

/// Options for the outcome of a given action in a [`LogEntry`]
#[derive(Debug, Serialize, Deserialize)]
pub enum Outcome {
    Successful,
    Failed,
}

/// A single log entry that specifies the actor, action, outcome, and
/// any related key for a logged event
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    actor: AccountName,
    secret_id: Option<KeyId>,
    date: DateTime,
    action: Action,
    outcome: Outcome,
}

impl LogEntry {
    pub fn new(
        actor: AccountName,
        secret_id: Option<KeyId>,
        action: Action,
        outcome: Outcome,
    ) -> Self {
        LogEntry {
            actor,
            secret_id,
            date: DateTime::now(),
            action,
            outcome,
        }
    }
}

impl Display for LogEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LogEntry: User <{:?}> performed action <{:?}> on {} with outcome <{:?}>",
            self.actor, self.action, self.date, self.outcome
        )
    }
}
