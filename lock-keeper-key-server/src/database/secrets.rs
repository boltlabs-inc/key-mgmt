//! Module for operations on secrets in the database.

use crate::{constants, LockKeeperServerError};
use lock_keeper::{
    constants::USER_ID,
    crypto::{Encrypted, KeyId, Secret, SigningKeyPair},
    types::database::{
        secrets::{StoredEncryptedSecret, StoredSigningKeyPair},
        user::{User, UserId},
    },
};
use mongodb::bson::doc;

use super::Database;

pub const REMOTE_SECRETS: &str = "remote_secrets";

impl Database {
    /// Add a [`StoredEncryptedSecret`] to a [`User`]'s list of arbitrary
    /// secrets
    pub async fn add_user_secret(
        &self,
        user_id: &UserId,
        secret: Encrypted<Secret>,
        key_id: KeyId,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let stored_secret = StoredEncryptedSecret::new(secret, key_id);
        let stored_secret_bson = mongodb::bson::to_bson(&stored_secret)?;
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$push":  { "secrets.arbitrary_secrets": stored_secret_bson } };
        let _ = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        Ok(())
    }

    /// Add a [`StoredSigningKeyPair`] to a [`User`]'s list of arbitrary
    /// secrets
    pub async fn add_server_imported_signing_key(
        &self,
        user_id: &UserId,
        secret: SigningKeyPair,
        key_id: KeyId,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let stored_secret = StoredSigningKeyPair::new(secret, key_id);
        let stored_secret_bson = mongodb::bson::to_bson(&stored_secret)?;
        let filter = doc! { USER_ID: user_id };
        let update =
            doc! { "$push":  { "secrets.server_created_signing_keys": stored_secret_bson } };
        let _ = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        Ok(())
    }

    /// Get a [`User`]'s [`StoredEncryptedSecret`] based on its [`KeyId`]
    pub async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<StoredEncryptedSecret, LockKeeperServerError> {
        // Get user collection
        let collection = self.inner.collection::<User>(constants::USERS);
        // Match on UserId and KeyId, update "retrieved" field to true
        let key_id_bson = mongodb::bson::to_bson(key_id)?;
        let filter = doc! { USER_ID: user_id, "secrets.arbitrary_secrets.key_id": key_id_bson };
        let update = doc! { "$set": { "secrets.arbitrary_secrets.$.retrieved": true } };
        let user = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;

        // Filter found user to return stored secret
        let stored_secret = user
            .secrets
            .arbitrary_secrets
            .into_iter()
            .find(|x| x.key_id == *key_id)
            .ok_or(LockKeeperServerError::KeyNotFound)?;

        Ok(stored_secret)
    }

    /// Add a [`StoredSigningKeyPair`] to a [`User`]'s list of arbitrary secrets
    /// TODO: This function temporarily stores an unencrypted key pair.
    /// WARNING: Do not use in production!
    pub async fn add_remote_secret(
        &self,
        user_id: &UserId,
        secret: SigningKeyPair,
        key_id: KeyId,
    ) -> Result<(), LockKeeperServerError> {
        let collection = self.inner.collection::<User>(constants::USERS);
        let stored_secret = StoredSigningKeyPair::new(secret, key_id);
        let stored_secret_bson = mongodb::bson::to_bson(&stored_secret)?;
        let filter = doc! { USER_ID: user_id };
        let update = doc! { "$push": { REMOTE_SECRETS: stored_secret_bson } };
        let _ = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;
        Ok(())
    }

    /// Get a [`User`]'s [`StoredSigningKeyPair`] based on its [`KeyId`]
    pub async fn get_user_signing_key(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<StoredSigningKeyPair, LockKeeperServerError> {
        // Get user collection
        let collection = self.inner.collection::<User>(constants::USERS);
        // Match on UserId and KeyId, update "retrieved" field to true
        let key_id_bson = mongodb::bson::to_bson(key_id)?;
        let filter =
            doc! { USER_ID: user_id, "secrets.server_created_signing_keys.key_id": key_id_bson };
        let update = doc! { "$set": { "secrets.server_created_signing_keys.$.retrieved": true } };
        let user = collection
            .find_one_and_update(filter, update, None)
            .await?
            .ok_or(LockKeeperServerError::InvalidAccount)?;

        // Filter found user to return stored secret
        let stored_secret = user
            .secrets
            .server_created_signing_keys
            .into_iter()
            .find(|x| x.key_id == *key_id)
            .ok_or(LockKeeperServerError::KeyNotFound)?;

        Ok(stored_secret)
    }
}
