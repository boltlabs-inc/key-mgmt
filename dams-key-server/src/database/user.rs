//! Module for operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use crate::{constants, DamsServerError};
use dams::{
    config::opaque::OpaqueCipherSuite,
    user::{AccountName, User, UserId},
};
use mongodb::{
    bson::{doc, oid::ObjectId},
    error::Error,
    Database,
};
use opaque_ke::ServerRegistration;

/// Create a new [`User`] with their authentication information and insert it
/// into the MongoDB database.
pub async fn create_user(
    db: &Database,
    user_id: &UserId,
    account_name: &AccountName,
    server_registration: &ServerRegistration<OpaqueCipherSuite>,
) -> Result<Option<ObjectId>, DamsServerError> {
    let collection = db.collection::<User>(constants::USERS);

    let new_user = User::new(
        user_id.clone(),
        account_name.clone(),
        server_registration.clone(),
    );
    let insert_one_res = collection.insert_one(new_user, None).await?;
    Ok(insert_one_res.inserted_id.as_object_id())
}

/// Find a [`User`] by their human-readable [`AccountName`].
pub async fn find_user(db: &Database, account_name: &AccountName) -> Result<Option<User>, Error> {
    let collection = db.collection::<User>(constants::USERS);
    let query = doc! {"account_name": account_name.to_string()};
    let user = collection.find_one(query, None).await?;
    Ok(user)
}

/// Find a [`User`] by their machine-readable [`UserId`].
pub async fn find_user_by_id(db: &Database, user_id: &UserId) -> Result<Option<User>, Error> {
    let collection = db.collection::<User>(constants::USERS);
    let query = doc! {"user_id": user_id.to_string()};
    let user = collection.find_one(query, None).await?;
    Ok(user)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use dams::{
        config::{opaque::OpaqueCipherSuite, server::DatabaseSpec},
        user::{AccountName, User, UserId},
    };
    use mongodb::{options::ClientOptions, Client};
    use opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
    };
    use rand::{CryptoRng, RngCore};

    use crate::{constants, database::connect_to_mongo, DamsServerError};

    use super::create_user;

    /// Locally simulates OPAQUE registration to get a valid
    /// `ServerRegistration` for remaining tests.
    fn server_registration(
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

    // Delete the entire db to avoid leftover issues from previous runs.
    async fn drop_db(mongodb_uri: &str, db_name: &str) -> Result<(), DamsServerError> {
        // Parse a connection string into an options struct
        let client_options = ClientOptions::parse(mongodb_uri).await?;
        // Get a handle to the deployment
        let client = Client::with_options(client_options)?;
        // Get a handle to the database
        let db = client.database(db_name);
        db.drop(None).await?;

        Ok(())
    }

    #[tokio::test]
    async fn multiple_connections_do_not_overwrite_db() -> Result<(), DamsServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "multiple_connections_dont_overwrite";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = connect_to_mongo(&db_spec).await?;

        let server_registration = &server_registration(&mut rng);

        // Add two users
        let uid1 = UserId::new(&mut rng)?;
        let _ = create_user(
            &db,
            &uid1,
            &AccountName::from_str("test user 1")?,
            server_registration,
        )
        .await?;

        let uid2 = UserId::new(&mut rng)?;
        let _ = create_user(
            &db,
            &uid2,
            &AccountName::from_str("test user 2")?,
            server_registration,
        )
        .await?;

        // Check that the database holds two users.
        assert_eq!(
            2,
            db.collection::<User>(constants::USERS)
                .estimated_document_count(None)
                .await?
        );

        // Reconnect and make sure it still has two users.
        let reconnected_db = connect_to_mongo(&db_spec).await?;
        assert_eq!(
            2,
            reconnected_db
                .collection::<User>(constants::USERS)
                .estimated_document_count(None)
                .await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn unique_indices_enforced() -> Result<(), DamsServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "unique_indices_are_enforced";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = connect_to_mongo(&db_spec).await?;

        // Add the "baseline" user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("unique@email.com")?;
        let server_registration = server_registration(&mut rng);
        let _ = create_user(&db, &user_id, &account_name, &server_registration).await?;

        // Matching UserIds can't be added.
        let different_an = AccountName::from_str("other@email.com")?;
        assert!(
            create_user(&db, &user_id, &different_an, &server_registration)
                .await
                .is_err()
        );

        // Matching AccountNames can't be added.
        let different_uid = UserId::new(&mut rng)?;
        assert!(
            create_user(&db, &different_uid, &account_name, &server_registration)
                .await
                .is_err()
        );

        // Matching both can't be added.
        assert!(
            create_user(&db, &user_id, &account_name, &server_registration)
                .await
                .is_err()
        );

        Ok(())
    }
}
