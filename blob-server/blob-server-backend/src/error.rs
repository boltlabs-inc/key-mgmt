use std::path::PathBuf;

use thiserror::Error;
use tonic::Status;

#[derive(Debug, Error)]
pub enum BlobServerError {
    #[error("Exceeded max database connection attempts")]
    ExceededMaxConnectionAttempts,
    #[error("Invalid config file: {0}")]
    InvalidConfig(String),
    #[error("Invalid log file path: {0}")]
    InvalidLogFilePath(PathBuf),

    /*
       Wrapped errors
    */
    #[error("Error hashing string")]
    Argon2HashError,
    #[error("Hash verification failed")]
    Argon2HashVerificationFailed,
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    /// Generic kitchen sink IO error. Use [LockKeeperServerError::FileIo] if
    /// the IO error is specifically related to working with files.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// IO error specific to file IO failing. Allows us to include the file that
    /// failed as part of the error.
    #[error("File IO error. Cause: {0}. On file: {1}")]
    FileIo(std::io::Error, PathBuf),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

impl BlobServerError {
    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig(message.into())
    }
}

impl From<BlobServerError> for Status {
    fn from(error: BlobServerError) -> Status {

        match error {
            | BlobServerError::ExceededMaxConnectionAttempts
            | BlobServerError::InvalidConfig(_)
            | BlobServerError::InvalidLogFilePath(_)
            | BlobServerError::Argon2HashError
            | BlobServerError::Argon2HashVerificationFailed
            | BlobServerError::Hyper(_)
            | BlobServerError::Io(_)
            | BlobServerError::FileIo(_, _)
            | BlobServerError::Sqlx(_)
            | BlobServerError::Toml(_) => Status::internal(error.to_string()),
        }
    }
}
