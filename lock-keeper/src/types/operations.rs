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

use crate::{
    types::database::user::{AccountName, UserId},
    LockKeeperError,
};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct RequestMetadata {
    account_name: AccountName,
    action: ClientAction,
    user_id: Option<UserId>,
}

impl RequestMetadata {
    pub fn new(account_name: &AccountName, action: ClientAction, user_id: Option<&UserId>) -> Self {
        Self {
            account_name: account_name.clone(),
            action,
            user_id: user_id.cloned(),
        }
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, LockKeeperError> {
        let vec = serde_json::to_vec(self)?;
        Ok(vec)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, LockKeeperError> {
        let metadata: Self = serde_json::from_slice(slice)?;
        Ok(metadata)
    }

    pub fn account_name(&self) -> &AccountName {
        &self.account_name
    }

    pub fn action(&self) -> ClientAction {
        self.action
    }

    pub fn user_id(&self) -> &Option<UserId> {
        &self.user_id
    }
}
