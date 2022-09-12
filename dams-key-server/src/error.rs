use crate::database::log;

use async_trait::async_trait;
use dams::{audit_log::Outcome, crypto::KeyId, user::LogIdentifier, ClientAction};
use mongodb::Database;
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum DamsServerError {
    #[error("Could not get service.")]
    MissingService,

    // Protocol errors
    #[error("Account does not exist")]
    AccountDoesNotExist,
    #[error("Invalid user_id")]
    InvalidUserId,
    #[error("Storage key is already set")]
    StorageKeyAlreadySet,
    #[error("Storage key is not set for this user")]
    StorageKeyNotSet,

    // Wrapped errors
    #[error(transparent)]
    Dams(#[from] dams::DamsError),
    #[error(transparent)]
    DamsChannel(#[from] dams::channel::ChannelError),
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
        Status::internal(error.to_string())
    }
}

#[async_trait]
pub trait LogExt {
    async fn log(
        self,
        db: &Database,
        actor: impl Into<LogIdentifier> + std::marker::Send,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Self;
}

#[async_trait]
impl<T: std::marker::Send> LogExt for Result<T, DamsServerError> {
    async fn log(
        self,
        db: &Database,
        actor: impl Into<LogIdentifier> + std::marker::Send,
        secret_id: Option<KeyId>,
        action: ClientAction,
    ) -> Self {
        if self.is_err() {
            log::create_log_entry(db, actor, secret_id, action, Outcome::Failed).await?;
        } else {
            log::create_log_entry(db, actor, secret_id, action, Outcome::Successful).await?;
        }
        self
    }
}
