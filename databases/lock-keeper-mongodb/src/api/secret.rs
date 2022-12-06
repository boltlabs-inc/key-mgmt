//! Operations on secrets in the database.

use crate::{constants::USERS, error::Error};
use lock_keeper::{
    constants::USER_ID,
    crypto::KeyId,
    types::database::{
        secrets::StoredSecret,
        user::{User, UserId},
    },
};
use lock_keeper_key_server::database::SecretFilter;
use mongodb::bson::doc;

use super::Database;

impl Database {
    /// Add a [`StoredSecret] to a [`User`]'s list of arbitrary
    /// secrets
    pub(crate) async fn add_user_secret(
        &self,
        user_id: &UserId,
        secret: StoredSecret,
    ) -> Result<(), Error> {
        let collection = self.handle.collection::<User>(USERS);
        let stored_secret_bson = mongodb::bson::to_bson(&secret)?;
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$push":  { "secrets": stored_secret_bson } };
        let _ = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(Error::InvalidAccount)?;
        Ok(())
    }

    /// Get a [`User`]'s [`StoredSecret`] based on its [`KeyId`]
    pub(crate) async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, Error> {
        // Get user collection
        let collection = self.handle.collection::<User>(USERS);
        // Match on UserId and KeyId, update "retrieved" field to true
        let key_id_bson = mongodb::bson::to_bson(key_id)?;
        let mut query_filter = doc! {
            USER_ID: user_id,
            "secrets.key_id": key_id_bson,
        };
        if let Some(st) = filter.secret_type {
            let _ = query_filter.insert("secrets.secret_type", st);
        }

        let update = doc! { "$set": { "secrets.$.retrieved": true } };
        let user = collection
            .find_one_and_update(query_filter, update, None)
            .await?
            .ok_or(Error::InvalidAccount)?;

        // Filter found user to return stored secret
        let stored_secret = user
            .secrets
            .into_iter()
            .find(|x| x.key_id == *key_id)
            .ok_or(Error::KeyNotFound)?;

        Ok(stored_secret)
    }
}
