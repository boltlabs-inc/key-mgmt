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
use tonic::metadata::{Ascii, MetadataValue};
use uuid::Uuid;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
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

impl TryFrom<&RequestMetadata> for MetadataValue<Ascii> {
    type Error = LockKeeperError;

    fn try_from(value: &RequestMetadata) -> Result<Self, Self::Error> {
        let bytes = serde_json::to_vec(value)?;
        Ok(MetadataValue::try_from(bytes)?)
    }
}

impl TryFrom<&MetadataValue<Ascii>> for RequestMetadata {
    type Error = LockKeeperError;

    fn try_from(value: &MetadataValue<Ascii>) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let metadata = serde_json::from_slice(bytes)?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseMetadata {
    pub request_id: Uuid,
}

impl TryFrom<ResponseMetadata> for MetadataValue<Ascii> {
    type Error = LockKeeperError;

    fn try_from(value: ResponseMetadata) -> Result<Self, Self::Error> {
        let bytes = serde_json::to_vec(&value)?;
        Ok(MetadataValue::try_from(bytes)?)
    }
}

impl TryFrom<&MetadataValue<Ascii>> for ResponseMetadata {
    type Error = LockKeeperError;

    fn try_from(value: &MetadataValue<Ascii>) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let metadata = serde_json::from_slice(bytes)?;
        Ok(metadata)
    }
}
