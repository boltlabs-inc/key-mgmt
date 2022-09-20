use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum DamsServerError {
    #[error("Could not get service.")]
    MissingService,

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
    Dams(#[from] dams::DamsError),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Bson(#[from] mongodb::bson::ser::Error),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),
    #[error(transparent)]
    EnvVar(#[from] std::env::VarError),
    #[error(transparent)]
    MongoDb(#[from] mongodb::error::Error),
}

impl From<opaque_ke::errors::ProtocolError> for DamsServerError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}

impl From<DamsServerError> for Status {
    fn from(error: DamsServerError) -> Status {
        match error {
            // Errors that are safe to return to the client
            DamsServerError::AccountAlreadyRegistered
            | DamsServerError::InvalidAccount
            | DamsServerError::KeyNotFound => Status::invalid_argument(error.to_string()),
            DamsServerError::StorageKeyAlreadySet | DamsServerError::StorageKeyNotSet => {
                Status::internal(error.to_string())
            }

            DamsServerError::TonicTransport(err) => Status::internal(err.to_string()),
            DamsServerError::TonicStatus(status) => status,
            // These errors are are sanitized in the [`DamsError`] module
            DamsServerError::Dams(err) => err.into(),

            // Errors that the client should not see
            DamsServerError::MissingService
            | DamsServerError::Hyper(_)
            | DamsServerError::Io(_)
            | DamsServerError::Bson(_)
            | DamsServerError::OpaqueProtocol(_)
            | DamsServerError::EnvVar(_)
            | DamsServerError::MongoDb(_) => Status::internal("Internal server error"),
        }
    }
}
