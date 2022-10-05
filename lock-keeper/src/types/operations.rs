//! Types related to server operations and the protocols they execute.

pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod register;
pub mod retrieve;
pub mod retrieve_audit_events;
pub mod retrieve_storage_key;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::EnumIter;

use crate::LockKeeperError;

/// Options for actions the Lock Keeper client can take.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, EnumIter)]
pub enum ClientAction {
    Authenticate,
    CreateStorageKey,
    Export,
    Generate,
    Register,
    Retrieve,
    RetrieveAuditEvents,
    RetrieveStorageKey,
}

impl FromStr for ClientAction {
    type Err = LockKeeperError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Authenticate" => Ok(ClientAction::Authenticate),
            "CreateStorageKey" => Ok(ClientAction::CreateStorageKey),
            "Export" => Ok(ClientAction::Export),
            "Generate" => Ok(ClientAction::Generate),
            "Register" => Ok(ClientAction::Register),
            "Retrieve" => Ok(ClientAction::Retrieve),
            "RetrieveAuditEvents" => Ok(ClientAction::RetrieveAuditEvents),
            "RetrieveStorageKey" => Ok(ClientAction::RetrieveStorageKey),
            _ => Err(LockKeeperError::InvalidClientAction),
        }
    }
}
