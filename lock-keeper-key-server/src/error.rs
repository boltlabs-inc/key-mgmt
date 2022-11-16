use crate::server::session_key_cache::SessionKeyCacheError;
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum LockKeeperServerError {
    #[error("Could not get service.")]
    MissingService,
    #[error("Private key was not provided.")]
    PrivateKeyMissing,

    #[error("Error in session keys cache.")]
    SessionKeyCache(#[from] SessionKeyCacheError),

    // Infrastructure errors
    #[error("Invalid OPAQUE directory")]
    InvalidOpaqueDirectory,

    // Protocol errors
    #[error("Account already registered")]
    AccountAlreadyRegistered,
    #[error("Invalid account")]
    InvalidAccount,
    #[error("Storage key is already set")]
    StorageKeyAlreadySet,
    #[error("Storage key is not set for this user")]
    StorageKeyNotSet,
    #[error("Key ID does not match any stored arbitrary key")]
    KeyNotFound,

    // Wrapped errors
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
    #[error(transparent)]
    Bson(#[from] mongodb::bson::ser::Error),
    #[error(transparent)]
    EnvVar(#[from] std::env::VarError),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    LockKeeper(#[from] lock_keeper::LockKeeperError),
    #[error(transparent)]
    MongoDb(#[from] mongodb::error::Error),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
    #[error(transparent)]
    StrumParseError(#[from] strum::ParseError),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),
    #[error(transparent)]
    WebPki(#[from] tokio_rustls::webpki::Error),
}

impl From<opaque_ke::errors::ProtocolError> for LockKeeperServerError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}

impl From<LockKeeperServerError> for Status {
    fn from(error: LockKeeperServerError) -> Status {
        use crate::server::session_key_cache::SessionKeyCacheError::*;

        match error {
            LockKeeperServerError::SessionKeyCache(ExpiredSessionKey) => {
                Status::unauthenticated("Session key expired")
            }
            // Errors that are safe to return to the client
            LockKeeperServerError::AccountAlreadyRegistered
            | LockKeeperServerError::InvalidAccount
            | LockKeeperServerError::KeyNotFound => Status::invalid_argument(error.to_string()),

            LockKeeperServerError::StorageKeyAlreadySet
            | LockKeeperServerError::StorageKeyNotSet => Status::internal(error.to_string()),

            LockKeeperServerError::TonicTransport(err) => Status::internal(err.to_string()),
            LockKeeperServerError::TonicStatus(status) => status,
            // These errors are are sanitized in the [`LockKeeperError`] module
            LockKeeperServerError::LockKeeper(err) => err.into(),

            // Errors that the client should not see
            LockKeeperServerError::MissingService
            | LockKeeperServerError::SessionKeyCache(_)
            | LockKeeperServerError::Hyper(_)
            | LockKeeperServerError::Io(_)
            | LockKeeperServerError::InvalidOpaqueDirectory
            | LockKeeperServerError::Bson(_)
            | LockKeeperServerError::Bincode(_)
            | LockKeeperServerError::OpaqueProtocol(_)
            | LockKeeperServerError::PrivateKeyMissing
            | LockKeeperServerError::EnvVar(_)
            | LockKeeperServerError::Rustls(_)
            | LockKeeperServerError::StrumParseError(_)
            | LockKeeperServerError::Toml(_)
            | LockKeeperServerError::MongoDb(_)
            | LockKeeperServerError::WebPki(_) => Status::internal("Internal server error"),
        }
    }
}
