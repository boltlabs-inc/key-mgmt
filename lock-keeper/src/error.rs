use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tonic::Status;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum LockKeeperError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    // Channel errors
    #[error("Invalid message")]
    InvalidMessage,
    #[error("No message received")]
    NoMessageReceived,

    // TLS errors
    #[error("Invalid private key")]
    InvalidPrivateKey,

    // OPAQUE errors
    #[error("Could not create opaque path directory")]
    InvalidOpaqueDirectory,
    #[error("Could not open user's home directory")]
    ProjectDirs,

    // Wrapped errors
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    InvalidUri(#[from] http::uri::InvalidUri),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error("tokio Sender error: {}", .0)]
    TokioSender(String),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    WebPki(#[from] tokio_rustls::webpki::Error),
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
            LockKeeperError::Crypto(_)
            | LockKeeperError::InvalidOpaqueDirectory
            | LockKeeperError::ProjectDirs
            | LockKeeperError::Bincode(_)
            | LockKeeperError::Io(_)
            | LockKeeperError::InvalidPrivateKey
            | LockKeeperError::InvalidUri(_)
            | LockKeeperError::OpaqueProtocol(_)
            | LockKeeperError::Rustls(_)
            | LockKeeperError::SerdeJson(_)
            | LockKeeperError::TokioSender(_)
            | LockKeeperError::Toml(_)
            | LockKeeperError::TonicStatus(_)
            | LockKeeperError::WebPki(_) => Status::internal("Internal server error"),
        }
    }
}
