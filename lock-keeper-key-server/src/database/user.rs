//! Module for operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use crate::{constants, LockKeeperServerError};
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    constants::{ACCOUNT_NAME, USER_ID},
    crypto::{Encrypted, StorageKey},
    types::database::user::{AccountName, User, UserId},
};
use mongodb::bson::{doc, oid::ObjectId};
use opaque_ke::ServerRegistration;

use super::Database;

pub const STORAGE_KEY: &str = "storage_key";

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
