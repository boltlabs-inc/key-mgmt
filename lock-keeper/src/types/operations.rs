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
pub mod retrieve_storage_key;

use crate::{
    crypto::CryptoError,
    types::database::{
        user::{AccountName, UserId},
        HexBytes,
    },
    LockKeeperError,
};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};
use tonic::metadata::{Ascii, MetadataValue};
use uuid::Uuid;

use super::Message;

/// Options for actions the Lock Keeper client can take.
#[derive(
    Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Display, EnumIter, EnumString,
)]
pub enum ClientAction {
    Authenticate,
    CreateStorageKey,
    ExportSecret,
    ExportSigningKey,
    GenerateSecret,
    GetUserId,
    ImportSigningKey,
    Logout,
    Register,
    RemoteGenerateSigningKey,
    RemoteSignBytes,
    RetrieveSecret,
    RetrieveAuditEvents,
    RetrieveSigningKey,
    RetrieveStorageKey,
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "HexBytes", into = "HexBytes")]
pub struct SessionId(Box<[u8; 16]>);

impl SessionId {
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Result<Self, LockKeeperError> {
        // Generate random bytes
        let mut id = [0_u8; 16];
        rng.try_fill(&mut id)
            .map_err(|_| CryptoError::RandomNumberGeneratorFailed)?;

        Ok(Self(Box::new(id)))
    }
}

impl From<SessionId> for HexBytes {
    fn from(session_id: SessionId) -> Self {
        (*session_id.0).into()
    }
}

impl TryFrom<HexBytes> for SessionId {
    type Error = LockKeeperError;

    fn try_from(bytes: HexBytes) -> Result<Self, Self::Error> {
        Ok(SessionId(Box::new(bytes.try_into()?)))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestMetadata {
    account_name: AccountName,
    action: ClientAction,
    user_id: Option<UserId>,
    session_id: Option<SessionId>,
    request_id: Uuid,
}

impl RequestMetadata {
    pub fn new(
        account_name: &AccountName,
        action: ClientAction,
        user_id: Option<&UserId>,
        session_id: Option<&SessionId>,
        request_id: Uuid,
    ) -> Self {
        Self {
            account_name: account_name.clone(),
            action,
            user_id: user_id.cloned(),
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

    pub fn user_id(&self) -> Option<&UserId> {
        self.user_id.as_ref()
    }

    pub fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    pub fn set_user_id(&mut self, user_id: UserId) {
        self.user_id = Some(user_id);
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
