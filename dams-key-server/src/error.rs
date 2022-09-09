use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum DamsServerError {
    #[error("Could not get service.")]
    MissingService,

    // Protocol errors
    #[error("Account already exists")]
    AccountAlreadyExists,
    #[error("Account does not exist")]
    AccountDoesNotExist,

    // Wrapped errors
    #[error(transparent)]
    Dams(#[from] dams::DamsError),
    #[error(transparent)]
    DamsChannel(#[from] dams::channel::ChannelError),
    #[error(transparent)]
    Hyoer(#[from] hyper::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
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
        Status::internal(error.to_string())
    }
}
