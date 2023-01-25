use lock_keeper::LockKeeperError;
use thiserror::Error;
use tonic::{Code, Status};

pub type Result<T> = std::result::Result<T, LockKeeperClientError>;

#[derive(Debug, Error)]
pub enum LockKeeperClientError {
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    #[error("Server returned failure")]
    ServerReturnedFailure,
    #[error("This key server requires TLS client authentication.")]
    ClientAuthMissing,
    #[error("Private key was not provided.")]
    PrivateKeyMissing,
    #[error("HTTPS connector was requested but TLS settings were missing from config.")]
    TlsConfigMissing,

    #[error("Account already registered")]
    AccountAlreadyRegistered,
    #[error("Export failed")]
    ExportFailed,
    #[error("Logout failed")]
    LogoutFailed,
    #[error("Invalid account")]
    InvalidAccount,
    #[error("Invalid login")]
    InvalidLogin,
    #[error("Invalid key retrieved")]
    InvalidKeyRetrieved,
    #[error("An unauthenticated channel is needed for this action")]
    UnauthenticatedChannelNeeded,
    #[error("An authenticated channel is needed for this action")]
    AuthenticatedChannelNeeded,

    // Wrapped errors
    #[error(transparent)]
    LockKeeper(LockKeeperError),
    #[error(transparent)]
    LockKeeperCrypto(#[from] lock_keeper::crypto::CryptoError),
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
    TonicStatus(Status),
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),
    #[error(transparent)]
    WebPki(#[from] tokio_rustls::webpki::Error),
}

impl From<opaque_ke::errors::ProtocolError> for LockKeeperClientError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        match error {
            opaque_ke::errors::ProtocolError::InvalidLoginError => Self::InvalidLogin,
            _ => Self::OpaqueProtocol(error),
        }
    }
}

// Convert `tonic::Status` errors to a more useful error type
impl From<Status> for LockKeeperClientError {
    fn from(status: Status) -> Self {
        match (status.code(), status.message()) {
            (Code::InvalidArgument, "Account already registered") => Self::AccountAlreadyRegistered,
            (Code::InvalidArgument, "Invalid account") => Self::InvalidAccount,
            (Code::Unknown, "connection error: received fatal alert: CertificateRequired") => {
                Self::ClientAuthMissing
            }
            _ => Self::TonicStatus(status),
        }
    }
}

// Ensure that wrapped `tonic::Status` errors are properly converted
impl From<LockKeeperError> for LockKeeperClientError {
    fn from(error: LockKeeperError) -> Self {
        match error {
            LockKeeperError::TonicStatus(status) => status.into(),
            _ => Self::LockKeeper(error),
        }
    }
}
