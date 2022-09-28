//! Audit events, and associated fields and types
//!
//! Includes possible events to log and statuses of those events

use crate::user::AccountName;

use crate::{crypto::KeyId, ClientAction};
use bson::DateTime;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use strum::IntoEnumIterator;

/// Options for the outcome of a given action in a [`AuditEvent`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl AuditEvent {
    pub fn action(&self) -> ClientAction {
        self.action.clone()
    }

    pub fn key_id(&self) -> Option<KeyId> {
        self.secret_id.clone()
    }

    pub fn date(&self) -> DateTime {
        self.date
    }

    pub fn status(&self) -> EventStatus {
        self.status.clone()
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

/// Options for which types of events to retrieve from the key server
#[derive(Debug, Serialize, Deserialize)]
pub enum EventType {
    All,
    SystemOnly,
    KeyOnly,
}

impl EventType {
    pub fn into_client_actions(self) -> Vec<ClientAction> {
        let system_only = vec![
            ClientAction::Authenticate,
            ClientAction::CreateStorageKey,
            ClientAction::Register,
            ClientAction::RetrieveAuditEvents,
            ClientAction::RetrieveStorageKey,
        ];
        match self {
            Self::All => ClientAction::iter().collect::<Vec<_>>(),
            Self::SystemOnly => system_only,
            Self::KeyOnly => ClientAction::iter()
                .filter(|x| !system_only.contains(x))
                .collect::<Vec<_>>(),
        }
    }
}

/// Optional parameters to filter [`AuditEvent`]s by
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEventOptions {
    pub key_ids: Option<Vec<KeyId>>,
    pub after_date: Option<DateTime>,
    pub before_date: Option<DateTime>,
}
