use thiserror::Error;

pub type Result<T> = std::result::Result<T, LockKeeperTestError>;

#[derive(Debug, Error)]
pub enum LockKeeperTestError {
    #[error("Invalid test type: {0}")]
    InvalidTestType(String),
    #[error("Failed to contact key server after maximum number of retries.")]
    WaitForServerTimedOut,

    // Wrapped Errors
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("LockKeeperError: {0:?}")]
    LockKeeper(#[from] lock_keeper::LockKeeperError),
    #[error("LockKeeperClientError: {0:?}")]
    LockKeeperClient(#[from] lock_keeper_client::LockKeeperClientError),
    #[error("LockKeeperServerError: {0:?}")]
    LockKeeperServer(#[from] lock_keeper_key_server::LockKeeperServerError),
    #[error("MongoDB error: {0:?}")]
    MongoDb(#[from] mongodb::error::Error),
    #[error("RandError: {0:?}")]
    Rand(#[from] rand::Error),
}
