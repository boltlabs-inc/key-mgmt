use async_trait::async_trait;
use lock_keeper::{
    infrastructure::logging,
    types::{database::user::UserId, operations::SessionId},
};
use lock_keeper_key_server::server::session_cache::{Session, SessionCache, SessionCacheError};
use std::time::Duration;

use crate::{config::Config, Error};
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client, Database as MongoDB, IndexModel,
};
use tracing::{info, instrument};

const SESSION_ID: &str = "session_id";
const TABLE: &str = "sessions";
const USER_ID: &str = "user_id";

/// Cache holding sessions, per user, after authentication. Maps
/// [`UserId`]s to their [`Session`]s. Sessions are tagged with a timestamp. A
/// session is considered invalid after the `expiration` time has elapsed.
pub struct MongodbSessionCache {
    handle: MongoDB,
    /// Time a session is considered valid for.
    session_expiration: Duration,
}

impl MongodbSessionCache {
    /// Create a new [`MongodbSessionCache`] with the specified session timeout.
    pub async fn new(config: Config) -> Result<Self, Error> {
        let handle = Self::connect(&config).await?;
        Ok(Self {
            handle,
            session_expiration: config.session_expiration,
        })
    }

    /// Connect to the MongoDB instance specified by the given [`Config`]
    #[instrument(err(Debug))]
    async fn connect(config: &Config) -> Result<MongoDB, Error> {
        info!("Connecting");
        // Parse a connection string into an options struct
        let client_options = ClientOptions::parse(&config.mongodb_uri).await?;
        // Get a handle to the MongoDB client
        let client = Client::with_options(client_options)?;
        // Get a handle to the database
        let db = client.database(&config.db_name);

        // Index to enforce that entries are dropped after `session_timeout`
        let enforce_session_timeout = IndexOptions::builder()
            .expire_after(config.session_expiration)
            .build();
        let session_timeout_index = IndexModel::builder()
            .keys(doc! {SESSION_ID: 1})
            .options(enforce_session_timeout)
            .build();

        // Apply timeout to the database
        let _created_index = db
            .collection::<Session>(TABLE)
            .create_indexes([session_timeout_index], None)
            .await?;

        Ok(db)
    }

    #[instrument(skip_all, err(Debug), fields(session_id))]
    async fn store_session(&self, session: Session) -> Result<(), Error> {
        logging::record_field("session_id", session.session_id());
        let collection = self.handle.collection::<Session>(TABLE);
        // Delete existing session(s) for this user before adding new one
        let user_id_bson = mongodb::bson::to_bson(session.user_id())?;
        let query = doc! { USER_ID: user_id_bson };
        let _ = collection.delete_many(query, None).await?;
        let _ = collection.insert_one(&session, None).await?;
        Ok(())
    }

    #[instrument(skip(self), err(Debug))]
    async fn find_session(&self, session_id: SessionId, user_id: UserId) -> Result<Session, Error> {
        let collection = self.handle.collection::<Session>(TABLE);
        let user_id_bson = mongodb::bson::to_bson(&user_id)?;
        let session_id_bson = mongodb::bson::to_bson(&session_id)?;
        let query = doc! { SESSION_ID: session_id_bson, USER_ID: user_id_bson };
        let session = collection
            .find_one(query.clone(), None)
            .await?
            .ok_or(Error::MissingSession)?;
        let elapsed = session.timestamp().to_system_time().elapsed()?;
        if elapsed >= self.session_expiration {
            info!("Session key is expired.");
            // We don't care about this expired key.
            let _ = collection.delete_one(query, None).await?;
            return Err(Error::ExpiredSession);
        }
        Ok(session)
    }

    #[instrument(skip(self), err(Debug))]
    async fn delete_session(&self, session_id: SessionId) -> Result<(), Error> {
        let collection = self.handle.collection::<Session>(TABLE);
        let session_id_bson = mongodb::bson::to_bson(&session_id)?;
        let query = doc! { SESSION_ID: session_id_bson };
        let _ = collection.delete_one(query, None).await?;
        Ok(())
    }
}

#[async_trait]
impl SessionCache for MongodbSessionCache {
    /// Add a new session for the specified user. The previous session for that
    /// user will be overwritten.
    async fn store_session(&self, session: Session) -> Result<(), SessionCacheError> {
        self.store_session(session).await?;
        Ok(())
    }

    /// Get the session for the specified user, if one exists.
    /// This function checks if the session has expired and returns an error
    /// instead.
    async fn find_session(
        &self,
        session_id: SessionId,
        user_id: UserId,
    ) -> Result<Session, SessionCacheError> {
        let session = self.find_session(session_id, user_id).await?;
        Ok(session)
    }

    /// Remove the session key for this user from the hashmap.
    async fn delete_session(&self, session_id: SessionId) -> Result<(), SessionCacheError> {
        self.delete_session(session_id).await?;
        Ok(())
    }
}
