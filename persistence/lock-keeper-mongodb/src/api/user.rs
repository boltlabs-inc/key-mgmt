//! Operations on users in the database.
//!
//! Functions in this module are used to perform CRUD operations
//! on the [`User`] model in the MongoDB database.

use crate::{
    constants::{STORAGE_KEY, USERS},
    error::Error,
};
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    constants::{ACCOUNT_NAME, USER_ID},
    crypto::{Encrypted, StorageKey},
    types::database::user::{AccountName, User, UserId},
};
use mongodb::bson::doc;
use opaque_ke::ServerRegistration;

use super::Database;

impl Database {
    /// Create a new [`User`] with their authentication information and insert
    /// it into the MongoDB database.
    pub(crate) async fn create_user(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<User, Error> {
        let collection = self.handle.collection::<User>(USERS);

        let new_user = User::new(
            user_id.clone(),
            account_name.clone(),
            server_registration.clone(),
        );

        let _ = collection.insert_one(&new_user, None).await?;
        Ok(new_user)
    }

    /// Find a [`User`] by their human-readable [`AccountName`].
    pub(crate) async fn find_user(
        &self,
        account_name: &AccountName,
    ) -> Result<Option<User>, Error> {
        let collection = self.handle.collection::<User>(USERS);
        let query = doc! { ACCOUNT_NAME: account_name.to_string() };
        let user = collection.find_one(query, None).await?;
        Ok(user)
    }

    /// Find a [`User`] by their machine-readable [`UserId`].
    pub(crate) async fn find_user_by_id(&self, user_id: &UserId) -> Result<Option<User>, Error> {
        let collection = self.handle.collection::<User>(USERS);
        let query = doc! { USER_ID: user_id };
        let user = collection.find_one(query, None).await?;
        Ok(user)
    }

    /// Delete a [`User`] by their [`UserId`]
    pub(crate) async fn delete_user(&self, user_id: &UserId) -> Result<(), Error> {
        let collection = self.handle.collection::<User>(USERS);
        let query = doc! { USER_ID: user_id };
        let result = collection.delete_one(query, None).await?;

        if result.deleted_count == 0 {
            Err(Error::InvalidAccount)
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
    /// - Returns a `InvalidAccount` if the given `user_id` does not exist.
    pub(crate) async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), Error> {
        let storage_key_bson = mongodb::bson::to_bson(&storage_key)?;

        let collection = self.handle.collection::<User>(USERS);
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$set": { STORAGE_KEY: storage_key_bson } };

        let user = collection.find_one_and_update(filter, update, None).await?;

        if user.is_none() {
            Err(Error::InvalidAccount)
        } else {
            Ok(())
        }
    }
}
