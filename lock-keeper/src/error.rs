//! Error type for all errors returned to code outside of this crate.

use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tonic::Status;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum LockKeeperError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    // Request errors
    #[error("Invalid client action")]
    InvalidClientAction,

    // Channel errors
    #[error("Invalid message")]
    InvalidMessage,
    #[error("No message received")]
    NoMessageReceived,

    // TLS errors
    #[error("Invalid private key")]
    InvalidPrivateKey,

    // Wrapped errors
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("tokio Sender error: {}", .0)]
    TokioSender(String),
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
            LockKeeperError::InvalidMessage => Status::invalid_argument(error.to_string()),
            LockKeeperError::NoMessageReceived => Status::deadline_exceeded(error.to_string()),
            // Errors that the client should not see
            LockKeeperError::InvalidClientAction
            | LockKeeperError::Crypto(_)
            | LockKeeperError::Io(_)
            | LockKeeperError::InvalidPrivateKey
            | LockKeeperError::OpaqueProtocol(_)
            | LockKeeperError::SerdeJson(_)
            | LockKeeperError::TokioSender(_)
            | LockKeeperError::TonicStatus(_) => Status::internal("Internal server error"),
        }
    }
}
