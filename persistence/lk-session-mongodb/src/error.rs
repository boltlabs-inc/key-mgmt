use lock_keeper_key_server::server::session_cache::SessionCacheError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Bson(#[from] mongodb::bson::ser::Error),
    #[error("Session has expired.")]
    ExpiredSession,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("No session for this user.")]
    MissingSession,
    #[error(transparent)]
    MongoDb(#[from] mongodb::error::Error),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
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
