use lock_keeper::{crypto::OpaqueSessionKey, types::database::user::UserId};
use thiserror::Error;

#[derive(Debug, Error, PartialOrd, PartialEq, Eq)]
pub enum SessionCacheError {
    #[error("TODO")]
    SessionKeyExists,
    #[error("Session key has expired.")]
    ExpiredSessionKey,
    #[error("No session key for this user.")]
    MissingSessionKey,
    #[error("An invariant of this type was not upheld.")]
    InternalInvariantError,
}

/// Cache holding our session keys, per user, after authentication. Maps
/// [`UserId`]s to [`OpaqueSessionKey`]s. Keys should be tagged with a
/// timestamp. A key is considered invalid after the expiration time has
/// elapsed.
pub trait SessionCache: Send + Sync {
    /// Add a new session key for the specified user. The previous key for that
    /// user should be overwritten.
    fn create_session(&mut self, user: UserId, key: OpaqueSessionKey);

    /// Get the session key for the specified user, if one exists.
    /// This function should check if the key has expired and return an error
    /// if so.
    fn find_session(&mut self, user: UserId) -> Result<OpaqueSessionKey, SessionCacheError>;

    /// Indicate that the session key for this user has expired. If the same
    /// user attempts to make a server call after expiring their session
    /// key, they should need to authenticate again first.
    fn delete_session(&mut self, user_id: UserId) -> Result<(), SessionCacheError>;
}
