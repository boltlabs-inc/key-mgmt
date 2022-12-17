use lock_keeper_postgres::PostgresError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, LockKeeperTestError>;

#[derive(Debug, Error)]
pub enum LockKeeperTestError {
    #[error("Client config missing for required environment: \"{0}\". Check TestEnvironments.toml if you're using the default environment config.")]
    MissingRequiredConfig(String),
    #[error("Invalid test type: {0}")]
    InvalidTestType(String),
    #[error("One or more test cases failed.")]
    TestFailed,
    #[error("Undefined environment: {0}")]
    UndefinedEnvironment(String),
    #[error("Could not contact environment {0}")]
    WaitForEnvironmentFailed(String),
    #[error("Failed to contact key server after maximum number of retries.")]
    WaitForServerTimedOut,
    #[error("Wrong error returned")]
    WrongErrorReturned,

    // Wrapped Errors
    #[error(transparent)]
    Clap(#[from] clap::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("LockKeeperError: {0:?}")]
    LockKeeper(#[from] lock_keeper::LockKeeperError),
    #[error("LockKeeperClientError: {0:?}")]
    LockKeeperClient(#[from] lock_keeper_client::LockKeeperClientError),
    #[error("LockKeeperServerError: {0:?}")]
    LockKeeperServer(#[from] lock_keeper_key_server::LockKeeperServerError),
    #[error("LockKeeperMongoDb error: {0:?}")]
    LkSessionMongodb(#[from] lk_session_mongodb::Error),
    #[error("RandError: {0:?}")]
    SessionCache(#[from] lock_keeper_key_server::server::session_cache::SessionCacheError),
    #[error("PostgresError error: {0:?}")]
    LockKeeperPostgres(#[from] PostgresError),
    #[error("RandError: {0:?}")]
    Rand(#[from] rand::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}
