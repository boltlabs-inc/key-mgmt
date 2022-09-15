use dams::DamsError;
use thiserror::Error;
use tonic::{Code, Status};

#[derive(Debug, Error)]
pub enum DamsClientError {
    #[error("Tried to connect to a server without an https link")]
    HttpNotAllowed,
    #[error("Server returned failure")]
    ServerReturnedFailure,

    #[error("Account already registered")]
    AccountAlreadyRegistered,
    #[error("Invalid account")]
    InvalidAccount,
    #[error("Invalid login")]
    InvalidLogin,

    // Wrapped errors
    #[error(transparent)]
    Dams(DamsError),
    #[error(transparent)]
    DamsCrypto(#[from] dams::crypto::CryptoError),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    TonicStatus(Status),
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),
}

impl From<opaque_ke::errors::ProtocolError> for DamsClientError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        match error {
            opaque_ke::errors::ProtocolError::InvalidLoginError => Self::InvalidLogin,
            _ => Self::OpaqueProtocol(error),
        }
    }
}

// Convert `tonic::Status` errors to a more useful error type
impl From<Status> for DamsClientError {
    fn from(status: Status) -> Self {
        match (status.code(), status.message()) {
            (Code::InvalidArgument, "Account already registered") => Self::AccountAlreadyRegistered,
            (Code::InvalidArgument, "Invalid account") => Self::InvalidAccount,
            _ => Self::TonicStatus(status),
        }
    }
}

// Ensure that wrapped `tonic::Status` errors are properly converted
impl From<DamsError> for DamsClientError {
    fn from(error: DamsError) -> Self {
        match error {
            DamsError::TonicStatus(status) => status.into(),
            _ => Self::Dams(error),
        }
    }
}
