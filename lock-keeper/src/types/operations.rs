//! Types related to server operations and the protocols they execute.

pub mod authenticate;
pub mod create_storage_key;
pub mod generate;
pub mod get_user_id;
pub mod import;
pub mod logout;
pub mod register;
pub mod remote_generate;
pub mod remote_sign_bytes;
pub mod retrieve_audit_events;
pub mod retrieve_secret;
pub mod retrieve_server_encrypted_blob;
pub mod retrieve_storage_key;
pub mod store_server_encrypted_blob;

use crate::{types::database::account::AccountName, LockKeeperError};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};
use tonic::metadata::{Ascii, MetadataValue};
use uuid::Uuid;

use super::Message;

/// Options for actions the Lock Keeper client can take.
/// We explicitly assign discriminant values to this type, as it will be stored
/// in the our database.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Display, EnumIter, EnumString, Hash,
)]
pub enum ClientAction {
    Authenticate = 0,
    CreateStorageKey = 1,
    ExportSecret = 2,
    ExportSigningKey = 3,
    GenerateSecret = 4,
    GetUserId = 5,
    ImportSigningKey = 6,
    Logout = 7,
    Register = 8,
    RemoteGenerateSigningKey = 9,
    RemoteSignBytes = 10,
    RetrieveSecret = 11,
    RetrieveAuditEvents = 12,
    RetrieveSigningKey = 13,
    RetrieveStorageKey = 14,
    RetrieveServerEncryptedBlob = 15,
    StoreServerEncryptedBlob = 16,
}

impl TryFrom<i64> for ClientAction {
    type Error = i64;

    fn try_from(v: i64) -> Result<Self, Self::Error> {
        match v {
            x if x == ClientAction::Authenticate as i64 => Ok(ClientAction::Authenticate),
            x if x == ClientAction::CreateStorageKey as i64 => Ok(ClientAction::CreateStorageKey),
            x if x == ClientAction::ExportSecret as i64 => Ok(ClientAction::ExportSecret),
            x if x == ClientAction::ExportSigningKey as i64 => Ok(ClientAction::ExportSigningKey),
            x if x == ClientAction::GenerateSecret as i64 => Ok(ClientAction::GenerateSecret),
            x if x == ClientAction::GetUserId as i64 => Ok(ClientAction::GetUserId),
            x if x == ClientAction::ImportSigningKey as i64 => Ok(ClientAction::ImportSigningKey),
            x if x == ClientAction::Logout as i64 => Ok(ClientAction::Logout),
            x if x == ClientAction::Register as i64 => Ok(ClientAction::Register),
            x if x == ClientAction::RemoteGenerateSigningKey as i64 => {
                Ok(ClientAction::RemoteGenerateSigningKey)
            }
            x if x == ClientAction::RemoteSignBytes as i64 => Ok(ClientAction::RemoteSignBytes),
            x if x == ClientAction::RetrieveServerEncryptedBlob as i64 => {
                Ok(ClientAction::RetrieveServerEncryptedBlob)
            }
            x if x == ClientAction::RetrieveSecret as i64 => Ok(ClientAction::RetrieveSecret),
            x if x == ClientAction::RetrieveAuditEvents as i64 => {
                Ok(ClientAction::RetrieveAuditEvents)
            }
            x if x == ClientAction::RetrieveSigningKey as i64 => {
                Ok(ClientAction::RetrieveSigningKey)
            }
            x if x == ClientAction::RetrieveStorageKey as i64 => {
                Ok(ClientAction::RetrieveStorageKey)
            }
            x if x == ClientAction::StoreServerEncryptedBlob as i64 => {
                Ok(ClientAction::StoreServerEncryptedBlob)
            }
            // Return value of offending integer.
            _ => Err(v),
        }
    }
}

/// Converts a serializable Rust type to and from the RPC [`Message`] type.
pub trait ConvertMessage: Sized + for<'a> Deserialize<'a> + Serialize {
    fn from_message(value: Message) -> Result<Self, LockKeeperError> {
        Ok(serde_json::from_slice(&value.content)?)
    }

    fn to_message(self) -> Result<Message, LockKeeperError> {
        let content = serde_json::to_vec(&self)?;
        Ok(Message { content })
    }
}

// Implements `ConvertMessage` for all types that implement `Serialize` and
// `Deserialize`.
impl<T: for<'a> Deserialize<'a> + Serialize> ConvertMessage for T {}

/// Metadata attached to each request to the server. Note that the request ID is
/// an ID for an entire operation, not each `ClientAction` that the operation is
/// composed of.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestMetadata {
    account_name: AccountName,
    action: ClientAction,
    session_id: Option<Uuid>,
    request_id: Uuid,
}

impl RequestMetadata {
    pub fn new(
        account_name: &AccountName,
        action: ClientAction,
        session_id: Option<&Uuid>,
        request_id: Uuid,
    ) -> Self {
        Self {
            account_name: account_name.clone(),
            action,
            session_id: session_id.cloned(),
            request_id,
        }
    }

    pub fn account_name(&self) -> &AccountName {
        &self.account_name
    }

    pub fn action(&self) -> ClientAction {
        self.action
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn session_id(&self) -> Option<&Uuid> {
        self.session_id.as_ref()
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

#[cfg(test)]
mod test {
    use crate::types::operations::ClientAction;
    use strum::IntoEnumIterator;

    /// Ensure our conversion function covers all cases.
    #[test]
    fn client_action_conversion_exhaustive() {
        for action in ClientAction::iter() {
            assert_eq!(action, ClientAction::try_from(action as i64).unwrap());
        }
    }
}
