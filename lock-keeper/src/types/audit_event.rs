//! Audit events, and associated fields and types
//!
//! Includes possible events to log and statuses of those events

use crate::{
    crypto::KeyId,
    types::{database::user::AccountName, operations::ClientAction},
};

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use strum::{Display, EnumString};
use time::OffsetDateTime;
use uuid::Uuid;

/// Options for the outcome of a given action in a [`AuditEvent`]

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Display, EnumString)]
pub enum EventStatus {
    Started,
    Successful,
    Failed,
}

/// A single entry that specifies the actor, action, outcome, and
/// any related key for a logged audit event.
/// We expect database implementors to create [AuditEvent] instances for us. So
/// we make all fields public.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_event_id: i64,
    pub account_name: AccountName,
    pub request_id: Uuid,
    pub key_id: Option<KeyId>,
    /// We use [OffsetDateTime] as this is compatible with SQLx. Easily
    /// convertible to a postgres' TIMESTAMPTZ type.
    pub timestamp: OffsetDateTime,
    pub client_action: ClientAction,
    pub status: EventStatus,
}

impl AuditEvent {
    pub fn request_id(&self) -> &Uuid {
        &self.request_id
    }

    pub fn action(&self) -> ClientAction {
        self.client_action
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    pub fn date(&self) -> OffsetDateTime {
        self.timestamp
    }

    pub fn status(&self) -> EventStatus {
        self.status
    }
}

impl Display for AuditEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Request ID: {}", self.request_id())?;
        if let Some(key_id) = self.key_id() {
            writeln!(f, "{key_id:?}")?;
        }
        writeln!(f, "{}", self.date())?;
        writeln!(f, "{}", self.action())?;
        writeln!(f, "{}", self.status())
    }
}

/// Options for which types of events to retrieve from the key server
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum EventType {
    All,
    SystemOnly,
    KeyOnly,
}

const ALL_ACTIONS: &[ClientAction] = &[
    ClientAction::Authenticate,
    ClientAction::CreateStorageKey,
    ClientAction::ExportSecret,
    ClientAction::ExportSigningKey,
    ClientAction::GenerateSecret,
    ClientAction::GetUserId,
    ClientAction::ImportSigningKey,
    ClientAction::Logout,
    ClientAction::Register,
    ClientAction::RemoteGenerateSigningKey,
    ClientAction::RemoteSignBytes,
    ClientAction::RetrieveSecret,
    ClientAction::RetrieveAuditEvents,
    ClientAction::RetrieveSigningKey,
    ClientAction::RetrieveStorageKey,
];

const SYSTEM_ONLY_ACTIONS: &[ClientAction] = &[
    ClientAction::Authenticate,
    ClientAction::CreateStorageKey,
    ClientAction::GetUserId,
    ClientAction::Logout,
    ClientAction::Register,
    ClientAction::RetrieveAuditEvents,
    ClientAction::RetrieveStorageKey,
];

const KEY_ONLY_ACTIONS: &[ClientAction] = &[
    ClientAction::ExportSecret,
    ClientAction::ExportSigningKey,
    ClientAction::GenerateSecret,
    ClientAction::ImportSigningKey,
    ClientAction::RemoteGenerateSigningKey,
    ClientAction::RemoteSignBytes,
    ClientAction::RetrieveSecret,
    ClientAction::RetrieveSigningKey,
];

impl EventType {
    pub fn client_actions(&self) -> &[ClientAction] {
        match self {
            Self::All => ALL_ACTIONS,
            Self::SystemOnly => SYSTEM_ONLY_ACTIONS,
            Self::KeyOnly => KEY_ONLY_ACTIONS,
        }
    }
}

/// Optional parameters to filter [`AuditEvent`]s by
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditEventOptions {
    pub key_ids: Vec<KeyId>,
    pub after_date: Option<OffsetDateTime>,
    pub before_date: Option<OffsetDateTime>,
    pub request_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;

    /// The ALL_ACTIONS constant exists so that we can use it as a constant
    /// without something like `lazy_static!`. This test ensures that any
    /// actions added to `ClientAction` are covered by this constant.
    #[test]
    fn all_actions_constant_includes_all_actions() {
        for action in ClientAction::iter() {
            assert!(ALL_ACTIONS.contains(&action))
        }
    }
}
