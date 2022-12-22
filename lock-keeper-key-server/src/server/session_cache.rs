use crate::{database::DataStore, server::Context, LockKeeperServerError};
use async_trait::async_trait;
use bson::DateTime;
use lock_keeper::{
    crypto::{Encrypted, OpaqueSessionKey},
    types::{database::user::UserId, operations::SessionId},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A single session with the LockKeeper key server, with a unique identifier
/// and a timestamp.
#[derive(Debug, Deserialize, Serialize)]
pub struct Session {
    session_id: SessionId,
    user_id: UserId,
    timestamp: DateTime,
    session_key: Encrypted<OpaqueSessionKey>,
}

impl Session {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn timestamp(&self) -> &DateTime {
        &self.timestamp
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Retrieve decrypted session key from session.
    pub(crate) fn session_key<DB: DataStore>(
        &self,
        context: &Context<DB>,
    ) -> Result<OpaqueSessionKey, LockKeeperServerError> {
        let session_key = self
            .session_key
            .clone()
            .decrypt_session_key(&context.config.remote_storage_key)?;
        Ok(session_key)
    }
}

#[derive(Debug, Error, PartialOrd, PartialEq, Eq)]
pub enum SessionCacheError {
    #[error("Session has expired.")]
    ExpiredSession,
    #[error("An error occurred within the cache. See cache logs.")]
    InternalCacheError,
    #[error("An invariant of this type was not upheld.")]
    InternalInvariantError,
    #[error("No session for this user.")]
    MissingSession,
    #[error("Session already exists for this user.")]
    SessionExists,
}

/// Cache holding our sessions, per user, after authentication. Maps
/// [`UserId`]s to [`Session`]s. Sessions should be tagged with a
/// timestamp. A session is considered invalid after the expiration time has
/// elapsed.
#[async_trait]
pub trait SessionCache: Send + Sync {
    /// Store a newly created session for the specified user. The previous
    /// session for that user should be overwritten.
    async fn store_session(&self, session: Session) -> Result<(), SessionCacheError>;

    /// Create a new session for the specified user. The previous session for
    /// that user should be overwritten.
    async fn create_session(
        &self,
        session_id: SessionId,
        user_id: UserId,
        session_key: Encrypted<OpaqueSessionKey>,
    ) -> Result<(), SessionCacheError> {
        let session = Session {
            session_id,
            user_id,
            timestamp: DateTime::now(),
            session_key,
        };
        self.store_session(session).await
    }

    /// Get the session for the specified user, if one exists.
    /// This function should check if the session has expired and return an
    /// error if so.
    async fn find_session(
        &self,
        session_id: SessionId,
        user_id: UserId,
    ) -> Result<Session, SessionCacheError>;

    /// Indicate that the session for this user has expired. If the same
    /// user attempts to make a server call after expiring their session,
    /// they should need to authenticate again first.
    async fn delete_session(&self, session_id: SessionId) -> Result<(), SessionCacheError>;
}
