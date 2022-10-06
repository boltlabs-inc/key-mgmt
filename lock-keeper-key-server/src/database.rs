//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use crate::constants;
use lock_keeper::{
    config::server::DatabaseSpec,
    defaults::server::{ACCOUNT_NAME, USER_ID},
    user::User,
};
use mongodb::{
    bson::doc,
    options::{ClientOptions, IndexOptions},
    Client, IndexModel,
};

use crate::error::LockKeeperServerError;

pub(crate) mod audit_event;
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

#[cfg(test)]
mod test {
    use crate::{database::Database, LockKeeperServerError};
    use lock_keeper::config::{opaque::OpaqueCipherSuite, server::DatabaseSpec};
    use mongodb::{options::ClientOptions, Client};
    use opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
    };
    use rand::{CryptoRng, RngCore};

    /// Locally simulates OPAQUE registration to get a valid
    /// `ServerRegistration` for remaining tests.
    pub(crate) fn server_registration(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> ServerRegistration<OpaqueCipherSuite> {
        let server_setup = ServerSetup::<OpaqueCipherSuite>::new(rng);
        let client_reg_start_result =
            ClientRegistration::<OpaqueCipherSuite>::start(rng, b"password").unwrap();
        let server_reg_start_result = ServerRegistration::<OpaqueCipherSuite>::start(
            &server_setup,
            client_reg_start_result.message,
            b"email@email.com",
        )
        .unwrap();
        let client_reg_finish_result = client_reg_start_result
            .state
            .finish(
                rng,
                b"password",
                server_reg_start_result.message,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();
        ServerRegistration::<OpaqueCipherSuite>::finish(client_reg_finish_result.message)
    }

    pub(crate) async fn setup_db(db_name: &str) -> Result<Database, LockKeeperServerError> {
        let mongodb_uri = "mongodb://localhost:27017";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;
        Ok(db)
    }

    // Delete the entire db to avoid leftover issues from previous runs.
    pub(crate) async fn drop_db(
        mongodb_uri: &str,
        db_name: &str,
    ) -> Result<(), LockKeeperServerError> {
        // Parse a connection string into an options struct
        let client_options = ClientOptions::parse(mongodb_uri).await?;
        // Get a handle to the deployment
        let client = Client::with_options(client_options)?;
        // Get a handle to the database
        let db = client.database(db_name);
        db.drop(None).await?;

        Ok(())
    }
}