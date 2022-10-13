//! Module for operations on secrets in the database.

use crate::{constants, LockKeeperServerError};
use lock_keeper::{
    constants::USER_ID,
    crypto::{Encrypted, KeyId, Secret},
    types::database::{
        secrets::StoredSecret,
        user::{User, UserId},
    },
};
use mongodb::bson::doc;

use super::Database;

pub const SECRETS: &str = "secrets";

impl Database {
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
}
