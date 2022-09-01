use thiserror::Error;
use tonic::Status;

use crate::{channel::ChannelError, crypto::CryptoError};

#[derive(Debug, Error)]
pub enum DamsError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Channel(#[from] ChannelError),

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
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    WebPki(#[from] tokio_rustls::webpki::Error),
}

impl From<opaque_ke::errors::ProtocolError> for DamsError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}

impl From<DamsError> for Status {
    fn from(error: DamsError) -> Self {
        let message = error.to_string();

        use DamsError::*;
        match error {
            Bincode(_)
            | Channel(_)
            | Crypto(_)
            | InvalidOpaqueDirectory
            | InvalidPrivateKey
            | InvalidUri(_)
            | Io(_)
            | OpaqueProtocol(_)
            | ProjectDirs
            | Rustls(_)
            | Toml(_)
            | WebPki(_) => Status::internal(message),
        }
    }
}
