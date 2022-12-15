//! Error type for all errors returned to code outside of this crate.

use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tonic::Status;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum LockKeeperError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    // Conversion errors
    #[error("Unknown secret type: {}", .0)]
    UnknownSecretType(String),
    #[error("Invalid secret type")]
    InvalidSecretType,
    #[error("Invalid KeyId length")]
    InvalidKeyIdLength,

    // Request errors
    #[error("Invalid client action")]
    InvalidClientAction,
    #[error("Network message missing required metadata")]
    MetadataNotFound,

    // Channel errors
    #[error("Invalid message")]
    InvalidMessage,
    #[error("No message received")]
    NoMessageReceived,
    #[error("Already authenticated")]
    AlreadyAuthenticated,
    #[error("This message should be send over an authenticated channel")]
    ShouldBeAuthenticated,

    // TLS errors
    #[error("Invalid private key")]
    InvalidPrivateKey,

    // Server side encryption error
    #[error("Invalid remote storage key")]
    InvalidRemoteStorageKey,

    // Wrapped errors
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("tokio Sender error: {}", .0)]
    TokioSender(String),
    #[error(transparent)]
    TonicMetadata(#[from] tonic::metadata::errors::InvalidMetadataValueBytes),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
}

impl From<opaque_ke::errors::ProtocolError> for LockKeeperError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}

impl<T> From<SendError<T>> for LockKeeperError {
    fn from(error: SendError<T>) -> Self {
        Self::TokioSender(error.to_string())
    }
}

impl From<LockKeeperError> for Status {
    fn from(error: LockKeeperError) -> Self {
        match error {
            // Errors that are safe to return to the client
            LockKeeperError::InvalidMessage
            | LockKeeperError::MetadataNotFound
            | LockKeeperError::UnknownSecretType(_)
            | LockKeeperError::InvalidSecretType => Status::invalid_argument(error.to_string()),
            LockKeeperError::NoMessageReceived => Status::deadline_exceeded(error.to_string()),
            // Errors that the client should not see
            LockKeeperError::InvalidClientAction
            | LockKeeperError::AlreadyAuthenticated
            | LockKeeperError::ShouldBeAuthenticated
            | LockKeeperError::Crypto(_)
            | LockKeeperError::Hex(_)
            | LockKeeperError::Io(_)
            | LockKeeperError::InvalidKeyIdLength
            | LockKeeperError::InvalidPrivateKey
            | LockKeeperError::InvalidRemoteStorageKey
            | LockKeeperError::OpaqueProtocol(_)
            | LockKeeperError::SerdeJson(_)
            | LockKeeperError::TokioSender(_)
            | LockKeeperError::TonicMetadata(_)
            | LockKeeperError::TonicStatus(_) => Status::internal("Internal server error"),
        }
    }
}
