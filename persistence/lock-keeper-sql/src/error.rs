use std::{array::TryFromSliceError, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error("sqlx error")]
    Sqlx(#[from] sqlx::Error),
    #[error("Could not serialize/deserialize data to/from databases.")]
    Serialization(#[from] bincode::Error),
    #[error("Slice size mismatch.")]
    WrongSliceSize(#[from] TryFromSliceError),
    #[error("No such entry in table.")]
    NoEntry,
    #[error("AuditEventDB to AuditEvent conversion failed: {0}")]
    AuditEventConversion(String),
    #[error("Unexpected number of rows returned.")]
    InvalidRowCountFound,
    #[error("Key ID exists but associated user ID or key type were incorrect.")]
    IncorrectAssociatedKeyData,
    #[error("Empty iterator for append_value_list function.")]
    EmptyIterator,
    #[error("Config file error.")]
    ConfigError(#[from] ConfigError),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Could not read config file {1}. Error: {0}.")]
    ConfigFileReadFailure(std::io::Error, PathBuf),
    #[error("Fail to read TOML file contents.")]
    TomlReadFailure(#[from] toml::de::Error),
    #[error("Missing database username.")]
    MissingUsername,
    #[error("Missing database password.")]
    MissingPassword,
}
