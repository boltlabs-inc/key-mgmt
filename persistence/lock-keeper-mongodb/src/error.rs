use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid account")]
    InvalidAccount,
    #[error("Key ID not found")]
    KeyNotFound,
    // Wrapped errors
    #[error(transparent)]
    Bson(#[from] mongodb::bson::ser::Error),
    #[error(transparent)]
    MongoDb(#[from] mongodb::error::Error),
}
