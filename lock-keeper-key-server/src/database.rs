//! Database for key-servers.
//!
//! This database will hold information on users and the secret material
//! they have stored in the key server.

use async_trait::async_trait;
use lock_keeper::{
    config::opaque::OpaqueCipherSuite,
    crypto::{Encrypted, KeyId, Secret, SigningKeyPair, StorageKey},
    types::{
        audit_event::{AuditEvent, AuditEventOptions, EventStatus, EventType},
        database::{
            secrets::{StoredEncryptedSecret, StoredSigningKeyPair},
            user::{AccountName, User, UserId},
        },
        operations::ClientAction,
    },
};
use opaque_ke::ServerRegistration;

/// Defines the expected interface between a key server and its database.
///
/// This trait definition is not complete. New trait methods may be added
/// in future server versions.
#[async_trait]
pub trait DataStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    // Audit event
    /// Create a new [`AuditEvent`] for the given actor, action, and outcome
    async fn create_audit_event(
        &self,
        actor: &AccountName,
        secret_id: &Option<KeyId>,
        action: ClientAction,
        status: EventStatus,
    ) -> Result<(), Self::Error>;

    /// Find [`AuditEvent`]s that correspond to the event type and provided
    /// filters
    async fn find_audit_events(
        &self,
        account_name: &AccountName,
        event_type: EventType,
        options: AuditEventOptions,
    ) -> Result<Vec<AuditEvent>, Self::Error>;

    // Secret
    /// Add a [`StoredEncryptedSecret`] to a [`User`]'s list of arbitrary
    /// secrets
    async fn add_user_secret(
        &self,
        user_id: &UserId,
        secret: Encrypted<Secret>,
        key_id: KeyId,
    ) -> Result<(), Self::Error>;

    /// Get a [`User`]'s [`StoredEncryptedSecret`] based on its [`KeyId`]
    async fn get_user_secret(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<StoredEncryptedSecret, Self::Error>;

    /// Add a [`StoredSigningKeyPair`] to a [`User`]'s list of arbitrary secrets
    /// TODO: This function will temporarily store an unencrypted key pair.
    /// WARNING: Do not use in production!
    async fn add_remote_secret(
        &self,
        user_id: &UserId,
        secret: SigningKeyPair,
        key_id: KeyId,
    ) -> Result<(), Self::Error>;

    /// Get a [`User`]'s [`StoredSigningKeyPair`] based on its [`KeyId`]
    async fn get_user_signing_key(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
    ) -> Result<StoredSigningKeyPair, Self::Error>;

    // User
    /// Create a new [`User`] with their authentication information and insert
    /// it into the database.
    async fn create_user(
        &self,
        user_id: &UserId,
        account_name: &AccountName,
        server_registration: &ServerRegistration<OpaqueCipherSuite>,
    ) -> Result<User, Self::Error>;

    /// Find a [`User`] by their human-readable [`AccountName`].
    async fn find_user(&self, account_name: &AccountName) -> Result<Option<User>, Self::Error>;

    /// Find a [`User`] by their machine-readable [`UserId`].
    async fn find_user_by_id(&self, user_id: &UserId) -> Result<Option<User>, Self::Error>;

    /// Delete a [`User`] by their [`UserId`]
    async fn delete_user(&self, user_id: &UserId) -> Result<(), Self::Error>;

    /// Set the `storage_key` field for the [`User`] associated with a given
    /// [`UserId`]
    /// Returns a `LockKeeperServerError::InvalidAccount` if the given
    /// `user_id` does not exist.
    async fn set_storage_key(
        &self,
        user_id: &UserId,
        storage_key: Encrypted<StorageKey>,
    ) -> Result<(), Self::Error>;
}
