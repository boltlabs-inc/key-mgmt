//! Types related to server operations and the protocols they execute.

pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod import;
pub mod register;
pub mod remote_generate;
pub mod remote_sign_bytes;
pub mod retrieve;
pub mod retrieve_audit_events;
pub mod retrieve_storage_key;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

/// Options for actions the Lock Keeper client can take.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Display, EnumIter, EnumString,
)]
pub enum ClientAction {
    Authenticate,
    CreateStorageKey,
    Export,
    ExportSigningKey,
    Generate,
    ImportSigningKey,
    Register,
    RemoteGenerate,
    RemoteSignBytes,
    Retrieve,
    RetrieveAuditEvents,
    RetrieveSigningKey,
    RetrieveStorageKey,
}
