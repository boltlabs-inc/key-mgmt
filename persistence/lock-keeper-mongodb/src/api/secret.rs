//! Operations on secrets in the database.

use crate::{constants::SECRETS, error::Error};
use lock_keeper::{
    constants::{KEY_ID, USER_ID},
    crypto::KeyId,
    types::database::{secrets::StoredSecret, user::UserId},
};
use lock_keeper_key_server::database::SecretFilter;
use mongodb::bson::doc;

use super::Database;

impl Database {
    /// Add a [`StoredSecret] to the to database.
    pub(crate) async fn add_user_secret(&self, secret: StoredSecret) -> Result<(), Error> {
        let collection = self.handle.collection::<StoredSecret>(SECRETS);
        let _ = collection.insert_one(&secret, None).await?;
        Ok(())
    }

    /// Get a [`StoredSecret`] based on its [`KeyId`].
    /// Ensures that the [`UserId`] also matches before returning the
    /// [`StoredSecret`]
    pub(crate) async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        filter: SecretFilter,
    ) -> Result<StoredSecret, Error> {
        // Get secret collection
        let collection = self.handle.collection::<StoredSecret>(SECRETS);
        // Match on UserId and KeyId, update "retrieved" field to true
        let user_id_bson = mongodb::bson::to_bson(user_id)?;
        let key_id_bson = mongodb::bson::to_bson(key_id)?;
        let mut query_filter = doc! {
            USER_ID: user_id_bson,
            KEY_ID: key_id_bson,
        };
        if let Some(st) = filter.secret_type {
            let _ = query_filter.insert("secret_type", st);
        }

        let update = doc! { "$set": { "retrieved": true } };
        let stored_secret = collection
            .find_one_and_update(query_filter, update, None)
            .await?
            .ok_or(Error::InvalidAccount)?;

        Ok(stored_secret)
    }
}
