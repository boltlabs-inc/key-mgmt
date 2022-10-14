//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use crate::constants;
use lock_keeper::{
    config::server::DatabaseSpec,
    constants::{ACCOUNT_NAME, USER_ID},
    types::database::user::User,
};
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client, IndexModel,
};

use crate::error::LockKeeperServerError;

pub(crate) mod audit_event;
pub(crate) mod secrets;
pub(crate) mod user;

#[derive(Clone, Debug)]
pub struct Database {
    inner: mongodb::Database,
}

impl Database {
    /// Connect to the MongoDB instance specified by the given [`DatabaseSpec`]
    pub async fn connect(database_spec: &DatabaseSpec) -> Result<Self, LockKeeperServerError> {
        // Parse a connection string into an options struct
        let client_options = ClientOptions::parse(&database_spec.mongodb_uri).await?;
        // Get a handle to the deployment
        let client = Client::with_options(client_options)?;
        // Get a handle to the database
        let db = client.database(&database_spec.db_name);

        // Enforce that the user ID is unique
        let enforce_uniqueness = IndexOptions::builder().unique(true).build();
        let user_id_index = IndexModel::builder()
            .keys(doc! {USER_ID: 1})
            .options(enforce_uniqueness)
            .build();

        // Enforce that the account name is unique
        let enforce_uniqueness = IndexOptions::builder().unique(true).build();
        let account_name_index = IndexModel::builder()
            .keys(doc! {ACCOUNT_NAME: 1})
            .options(enforce_uniqueness)
            .build();

        // Apply uniqueness to the database
        let _created_indices = db
            .collection::<User>(constants::USERS)
            .create_indexes([user_id_index, account_name_index], None)
            .await?;

        Ok(Self { inner: db })
    }
}
