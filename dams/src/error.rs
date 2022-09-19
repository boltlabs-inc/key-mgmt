use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tonic::Status;

use crate::crypto::CryptoError;

#[derive(Debug, Error)]
pub enum DamsError {
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
    #[error("tokio Sender error: {}", .0)]
    TokioSender(String),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    WebPki(#[from] tokio_rustls::webpki::Error),
}

impl From<opaque_ke::errors::ProtocolError> for DamsError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}

impl<T> From<SendError<T>> for DamsError {
    fn from(error: SendError<T>) -> Self {
        Self::TokioSender(error.to_string())
    }
}

impl From<DamsError> for Status {
    fn from(error: DamsError) -> Self {
        match error {
            // Errors that are safe to return to the client
            DamsError::InvalidMessage => Status::invalid_argument(error.to_string()),
            DamsError::NoMessageReceived => Status::deadline_exceeded(error.to_string()),

            // Errors that the client should not see
            DamsError::Crypto(_)
            | DamsError::InvalidOpaqueDirectory
            | DamsError::ProjectDirs
            | DamsError::Bincode(_)
            | DamsError::Io(_)
            | DamsError::InvalidPrivateKey
            | DamsError::InvalidUri(_)
            | DamsError::OpaqueProtocol(_)
            | DamsError::Rustls(_)
            | DamsError::TokioSender(_)
            | DamsError::Toml(_)
            | DamsError::TonicStatus(_)
            | DamsError::WebPki(_) => Status::internal("Internal server error"),
        }
    }
}
