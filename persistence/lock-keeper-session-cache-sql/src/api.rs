use async_trait::async_trait;
use lock_keeper::{
    crypto::{Encrypted, OpaqueSessionKey},
    infrastructure::logging,
    types::database::account::AccountId,
};
use lock_keeper_key_server::server::session_cache::{Session, SessionCache, SessionCacheError};
use sqlx::{postgres::PgPoolOptions, types::time::OffsetDateTime, PgPool};
use std::sync::Arc;
use uuid::Uuid;

use crate::{config::Config, types::SessionDB, Error};
use tracing::{error, info, instrument};

/// Cache holding sessions, per user, after authentication. Maps
/// [`AccountId`]s to their [`Session`]s. Sessions are tagged with a timestamp.
/// A session is considered invalid after the `expiration` time has elapsed.
pub struct PostgresSessionCache {
    config: Arc<Config>,
    /// PgPool is already implemented in terms of an Arc. No need to wrap it.
    connection_pool: PgPool,
}

impl PostgresSessionCache {
    #[instrument(skip_all, err(Debug))]
    pub async fn connect(config: Config) -> Result<Self, Error> {
        info!("Connecting to database {:?}", config);

        let mut attempts = 0;

        // We have to use `loop` instead of `while` here so that we can return a value
        // after a successful connection.
        let pool = loop {
            if attempts > config.connection_retries {
                return Err(Error::ExceededMaxConnectionAttempts);
            }

            // Create a connection pool based on our config.
            let pool = PgPoolOptions::new()
                .max_connections(config.max_connections)
                .acquire_timeout(config.connection_timeout)
                .connect(&config.uri())
                .await;

            match pool {
                Ok(pool) => break pool,
                Err(e) => {
                    attempts += 1;
                    error!("{e}");
                    error!(
                        "Failed to connect to db. Attempts: {attempts}. Retrying in {:?}",
                        config.connection_retry_delay
                    );
                    tokio::time::sleep(config.connection_retry_delay).await;
                }
            }
        };

        Ok(PostgresSessionCache {
            config: Arc::new(config),
            connection_pool: pool,
        })
    }

    pub fn db_name(&self) -> &str {
        &self.config.db_name
    }
}

#[async_trait]
impl SessionCache for PostgresSessionCache {
    /// Add a new session for the specified user. The previous session for that
    /// user will be overwritten.
    async fn create_session(
        &self,
        account_id: AccountId,
        session_key: Encrypted<OpaqueSessionKey>,
    ) -> Result<Uuid, SessionCacheError> {
        let session_id = self.create_session(account_id, session_key).await?;
        logging::record_field("session_id", &session_id);
        Ok(session_id)
    }

    /// Get the session for the specified user, if one exists.
    /// This function checks if the session has expired and returns an error
    /// instead.
    async fn find_session(&self, session_id: Uuid) -> Result<Session, SessionCacheError> {
        Ok(self.find_session(session_id).await?)
    }

    /// Remove the session key for this user from the hashmap.
    async fn delete_session(&self, session_id: Uuid) -> Result<(), SessionCacheError> {
        Ok(self.delete_session(session_id).await?)
    }
}

impl PostgresSessionCache {
    /// Add a new session for the specified user. The previous session for that
    /// user will be overwritten.
    #[instrument(skip_all, err(Debug), fields(account_id=?account_id, session_id))]
    async fn create_session(
        &self,
        account_id: AccountId,
        session_key: Encrypted<OpaqueSessionKey>,
    ) -> Result<Uuid, Error> {
        info!("Creating session.");

        let session_key = bincode::serialize(&session_key)?;

        let session_id = sqlx::query!(
            "INSERT INTO Session (account_id, session_key) \
             VALUES ($1, $2) \
             RETURNING session_id",
            account_id.0,
            session_key,
        )
        .fetch_one(&self.connection_pool)
        .await?
        .session_id;

        logging::record_field("session_id", &session_id);

        Ok(session_id)
    }

    /// Get the session for the specified user, if one exists.
    /// This function checks if the session has expired and returns an error
    /// instead.
    #[instrument(skip(self), err(Debug))]
    async fn find_session(&self, session_id: Uuid) -> Result<Session, Error> {
        let session_db = sqlx::query_as!(
            SessionDB,
            "SELECT session_id, account_id, timestamp, session_key \
            FROM Session \
            WHERE session_id=$1",
            session_id,
        )
        .fetch_optional(&self.connection_pool)
        .await?;

        let session: Session = match session_db {
            Some(session_db) => session_db.try_into()?,
            None => return Err(Error::MissingSession),
        };

        let elapsed = OffsetDateTime::now_utc() - session.timestamp;
        if elapsed >= self.config.session_expiration {
            info!("Session key is expired.");
            self.delete_session(session_id).await?;
            return Err(Error::ExpiredSession);
        }

        Ok(session)
    }

    /// Remove the session key for this user from the hashmap.
    #[instrument(skip(self), err(Debug))]
    async fn delete_session(&self, session_id: Uuid) -> Result<(), Error> {
        info!("Deleting session.");

        let _ = sqlx::query!("DELETE FROM Session WHERE session_id=$1", session_id,)
            .execute(&self.connection_pool)
            .await?;

        Ok(())
    }
}
