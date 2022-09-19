//! Module for operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use crate::{constants, LockKeeperServerError};
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::{Encrypted, KeyId, Secret, StorageKey},
    user::{AccountName, StoredSecret, User, UserId},
};
use mongodb::bson::{doc, oid::ObjectId};
use opaque_ke::ServerRegistration;

use super::Database;

pub const ACCOUNT_NAME: &str = "account_name";
pub const STORAGE_KEY: &str = "storage_key";
pub const SECRETS: &str = "secrets";
pub const USER_ID: &str = "user_id";

impl Database {
    /// Create a new [`User`] with their authentication information and insert
    /// it into the MongoDB database.
    pub async fn create_user(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<Option<ObjectId>, LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);

        let new_user = User::new(
            user_id.clone(),
            account_name.clone(),
            server_registration.clone(),
        );

        let insert_one_res = collection.insert_one(new_user, None).await?;
        Ok(insert_one_res.inserted_id.as_object_id())
    }

    /// Find a [`User`] by their human-readable [`AccountName`].
    pub async fn find_user(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<User>, LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let query = doc! { ACCOUNT_NAME: account_name.to_string() };
        let user = collection.find_one(query, None).await?;
        Ok(user)
    }

    /// Find a [`User`] by their machine-readable [`UserId`].
    pub async fn find_user_by_id(
        &self,
        user_id: &UserId,
    ) -> Result<Option<User>, LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let query = doc! { USER_ID: user_id };
        let user = collection.find_one(query, None).await?;
        Ok(user)
    }

    /// Delete a [`User`] by their [`UserId`]
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let query = doc! { USER_ID: user_id };
        let result = collection.delete_one(query, None).await?;

        if result.deleted_count == 0 {
            Err(LockKeeperServerError::InvalidAccount)
        } else {
            Ok(())
        }
    }

    /// Add a [`StoredSecret`] to a [`User`]'s list of arbitrary secrets
    pub async fn add_user_secret(
        &self,
        user_id: &UserId,
        secret: Encrypted<Secret>,
        key_id: KeyId,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let stored_secret = StoredSecret::new(secret, key_id);
        let stored_secret_bson = mongodb::bson::to_bson(&stored_secret)?;
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$push": { SECRETS: stored_secret_bson } };
        let _ = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        Ok(())
    }

    /// Get a [`User`]'s [`StoredSecret`] based on its [`KeyId`]
    pub async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<StoredSecret, LockKeeperServerError> {
        // Get user collection
        let collection = self.inner.collection::<User>(constants::USERS);
        // Match on UserId and KeyId, update "retrieved" field to true
        let key_id_bson = mongodb::bson::to_bson(key_id)?;
        let filter = doc! { USER_ID: user_id, "secrets.key_id": key_id_bson };
        let update = doc! { "$set": { "secrets.$.retrieved": true } };
        let user = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;

        // Filter found user to return stored secret
        let stored_secret = user
            .secrets
            .into_iter()
            .find(|x| x.key_id == *key_id)
            .ok_or(LockKeeperServerError::KeyNotFound)?;

        Ok(stored_secret)
    }

    /// Set the `storage_key` field for the [`User`] associated with a given
    /// [`UserId`]
    /// ## Errors
    /// - Returns a `bson::Error` if the storage key cannot be converted to BSON
    /// - Returns a `mongodb::Error` if there is a problem connecting to the
    ///   database
    /// - Returns a `LockKeeperServerError::InvalidAccount` if the given
    ///   `user_id` does not exist.
    pub async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), LockKeeperServerError> {
        let storage_key_bson = mongodb::bson::to_bson(&storage_key)?;

        let collection = self.inner.collection::<User>(constants::USERS);
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$set": { STORAGE_KEY: storage_key_bson } };

        let user = collection.find_one_and_update(filter, update, None).await?;

        if user.is_none() {
            Err(LockKeeperServerError::InvalidAccount)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;

    use generic_array::{typenum::U64, GenericArray};
    use lock_keeper::{
        config::{opaque::OpaqueCipherSuite, server::DatabaseSpec},
        crypto::OpaqueExportKey,
        user::{AccountName, User, UserId},
    };
    use mongodb::{options::ClientOptions, Client};
    use opaque_ke::{
        ClientRegistration, ClientRegistrationFinishParameters, ServerRegistration, ServerSetup,
    };
    use rand::{CryptoRng, Rng, RngCore};

    use crate::{constants, database::Database, LockKeeperServerError};

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
    async fn drop_db(mongodb_uri: &str, db_name: &str) -> Result<(), LockKeeperServerError> {
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
    async fn user_findable_by_account_name() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "user_findable_by_account_name";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        // Add the "baseline" user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("user@email.com")?;

        let server_registration = server_registration(&mut rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        let user = db.find_user(&account_name).await?.unwrap();
        assert_eq!(user.account_name, account_name);

        Ok(())
    }

    #[tokio::test]
    async fn user_findable_by_id() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "user_findable_by_id";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        // Add the "baseline" user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("user@email.com")?;

        let server_registration = server_registration(&mut rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        let user = db.find_user(&account_name).await?.unwrap();
        assert_eq!(user.user_id, user_id);

        let user = db.find_user_by_id(&user_id).await?;
        assert!(user.is_some());

        let user = user.unwrap();
        assert_eq!(user.user_id, user_id);

        Ok(())
    }

    #[tokio::test]
    async fn multiple_connections_do_not_overwrite_db() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "multiple_connections_dont_overwrite";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        let server_registration = &server_registration(&mut rng);

        // Add two users
        let uid1 = UserId::new(&mut rng)?;
        let _ = db
            .create_user(
                &uid1,
                &AccountName::from_str("test user 1")?,
                server_registration,
            )
            .await?;

        let uid2 = UserId::new(&mut rng)?;
        let _ = db
            .create_user(
                &uid2,
                &AccountName::from_str("test user 2")?,
                server_registration,
            )
            .await?;

        // Check that the database holds two users.
        assert_eq!(
            2,
            db.inner
                .collection::<User>(constants::USERS)
                .estimated_document_count(None)
                .await?
        );

        // Reconnect and make sure it still has two users.
        let reconnected_db = Database::connect(&db_spec).await?;
        assert_eq!(
            2,
            reconnected_db
                .inner
                .collection::<User>(constants::USERS)
                .estimated_document_count(None)
                .await?
        );

        Ok(())
    }

    #[tokio::test]
    async fn unique_indices_enforced() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "unique_indices_are_enforced";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        // Add the "baseline" user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("unique@email.com")?;

        let server_registration = server_registration(&mut rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        // Matching UserIds can't be added.
        let different_an = AccountName::from_str("other@email.com")?;
        assert!(db
            .create_user(&user_id, &different_an, &server_registration)
            .await
            .is_err());

        // Matching AccountNames can't be added.
        let different_uid = UserId::new(&mut rng)?;
        assert!(db
            .create_user(&different_uid, &account_name, &server_registration)
            .await
            .is_err());

        // Matching both can't be added.
        assert!(db
            .create_user(&user_id, &account_name, &server_registration)
            .await
            .is_err());

        Ok(())
    }

    #[tokio::test]
    async fn user_is_deleted() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "user_is_deleted";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        // Add the user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("user@email.com")?;

        let server_registration = server_registration(&mut rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        // Ensure that the user was created
        let user = db.find_user_by_id(&user_id).await?;
        assert!(user.is_some());

        // Delete the user
        db.delete_user(&user_id).await?;

        // Ensure that the user was deleted
        let user = db.find_user_by_id(&user_id).await?;
        assert!(user.is_none());

        // Ensure that an error is returned if the user is deleted again
        let result = db.delete_user(&user_id).await;
        assert!(matches!(result, Err(LockKeeperServerError::InvalidAccount)));

        Ok(())
    }

    #[tokio::test]
    /// Test that `set_storage_key` works correctly
    async fn storage_key_is_set() -> Result<(), LockKeeperServerError> {
        let mut rng = rand::thread_rng();
        let mongodb_uri = "mongodb://localhost:27017";
        let db_name = "storage_key_is_set";
        let db_spec = DatabaseSpec {
            mongodb_uri: mongodb_uri.to_string(),
            db_name: db_name.to_string(),
        };

        // Clean up previous runs and make fresh connection
        drop_db(mongodb_uri, db_name).await?;
        let db = Database::connect(&db_spec).await?;

        // Add the user.
        let user_id = UserId::new(&mut rng)?;
        let account_name = AccountName::from_str("user@email.com")?;

        let server_registration = server_registration(&mut rng);
        let _ = db
            .create_user(&user_id, &account_name, &server_registration)
            .await?;

        // Ensure that the user was created an no storage key is set
        let user = db.find_user(&account_name).await?.unwrap();
        assert!(user.storage_key.is_none());

        // Create a storage key
        let export_key = create_test_export_key(&mut rng);
        let storage_key = export_key
            .clone()
            .create_and_encrypt_storage_key(&mut rng, &user_id)
            .unwrap();

        // Set storage key and check that it is correct in the database
        db.set_storage_key(&user_id, storage_key.clone()).await?;

        let user = db.find_user(&account_name).await?.unwrap();
        assert_eq!(user.storage_key, Some(storage_key.clone()));

        Ok(())
    }

    // Create an export key for testing using random bytes
    fn create_test_export_key(rng: &mut (impl CryptoRng + RngCore)) -> OpaqueExportKey {
        let mut key = [0_u8; 64];
        rng.try_fill(&mut key)
            .expect("Failed to generate random key");

        // We can't create an export key directly from bytes so we convert it to a
        // GenericArray first.
        let key: GenericArray<u8, U64> = key.into();

        key.into()
    }
}
