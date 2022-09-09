use thiserror::Error;

#[derive(Debug, Error)]
pub enum DamsClientError {
    #[error("Tried to connect to a server without an https link")]
    HttpNotAllowed,
    #[error("Server returned failure")]
    ServerReturnedFailure,

    // Protocol errors
    #[error("Registration failed")]
    RegistrationFailed,
    #[error("Authentication failed")]
    AuthenticationFailed,

    // Wrapped errors
    #[error(transparent)]
    Dams(#[from] dams::DamsError),
    #[error(transparent)]
    DamsCrypto(#[from] dams::crypto::CryptoError),
    #[error(transparent)]
    DamsChannel(#[from] dams::channel::ChannelError),
    #[error("OPAQUE protocol error: {}", .0)]
    OpaqueProtocol(opaque_ke::errors::ProtocolError),
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),
}

impl From<opaque_ke::errors::ProtocolError> for DamsClientError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::OpaqueProtocol(error)
    }
}
