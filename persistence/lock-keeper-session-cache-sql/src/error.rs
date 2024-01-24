use std::{array::TryFromSliceError, path::PathBuf};

use lock_keeper_key_server::server::session_cache::SessionCacheError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to connect to database after maximum number of attempts")]
    ExceededMaxConnectionAttempts,
    #[error("Could not serialize/deserialize data to/from databases.")]
    Bincode(#[from] bincode::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("Session has expired.")]
    ExpiredSession,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("No session for this user.")]
    MissingSession,
    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("Slice size mismatch.")]
    WrongSliceSize(#[from] TryFromSliceError),
}

impl From<Error> for SessionCacheError {
    fn from(error: Error) -> Self {
        match error {
            Error::ExpiredSession => Self::ExpiredSession,
            Error::MissingSession => Self::MissingSession,
            _ => Self::InternalCacheError,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Could not read config file {1}. Error: {0}.")]
    ConfigFileReadFailure(std::io::Error, PathBuf),
    #[error("Failed to read TOML file contents: {0}")]
    TomlReadFailure(#[from] toml::de::Error),
    #[error("Missing session cache username.")]
    MissingUsername,
    #[error("Missing session cache password.")]
    MissingPassword,
}
